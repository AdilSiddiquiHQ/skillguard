/**
 * Precision and recall harness.
 *
 * A security scanner is only worth installing if it stays quiet on legitimate
 * work. This suite is the counterweight to the evasion tests:
 *
 *   - `corpus/clean`      realistic, well-formed skills plus reference docs that
 *                         *mention* dangerous things. They must produce zero
 *                         critical/high findings.
 *   - `corpus/malicious`  labelled attacks. They must still be caught.
 *   - the targeted cases  lock in each false positive that was found by
 *                         scanning real public skill repositories, so a future
 *                         rule change cannot quietly reintroduce it.
 */

import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { test } from 'node:test';

import { scan } from '../src/scan.js';
import { makeSkill, skillMarkdown, testConfig } from './helpers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLEAN = join(HERE, 'corpus', 'clean');
const MALICIOUS = join(HERE, 'corpus', 'malicious');

function scanDir(dir) {
  return scan([dir], { cwd: HERE, config: testConfig() });
}

function allFindings(report) {
  return report.skills.flatMap((skill) =>
    skill.findings.map((finding) => ({ ...finding, skill: skill.name }))
  );
}

function ruleIds(report) {
  return new Set(allFindings(report).map((f) => f.ruleId));
}

// ---------------------------------------------------------------------------
// Corpus: precision
// ---------------------------------------------------------------------------

test('clean corpus produces no critical or high findings', () => {
  const severe = allFindings(scanDir(CLEAN)).filter(
    (f) => f.severity === 'critical' || f.severity === 'high'
  );
  assert.deepEqual(
    severe.map((f) => `${f.severity} ${f.ruleId} ${f.file}:${f.line}`),
    [],
    'clean, well-formed skills must not produce severe findings'
  );
});

test('clean corpus is near-silent overall', () => {
  const findings = allFindings(scanDir(CLEAN));
  assert.ok(
    findings.length <= 1,
    `expected at most 1 finding across the clean corpus, got ${findings.length}: ${findings
      .map((f) => `${f.ruleId}@${f.file}:${f.line}`)
      .join(', ')}`
  );
});

test('clean corpus discovers every sample', () => {
  const report = scanDir(CLEAN);
  assert.equal(report.skills.length, 7);
  assert.ok(report.skills.every((s) => s.verdict === 'pass'));
});

// ---------------------------------------------------------------------------
// Corpus: recall
// ---------------------------------------------------------------------------

test('malicious corpus: every sample produces a high or critical finding', () => {
  const report = scanDir(MALICIOUS);
  assert.equal(report.skills.length, 8);
  for (const skill of report.skills) {
    const severe = skill.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    assert.ok(severe.length > 0, `${skill.name} must be caught, got none`);
  }
});

test('malicious corpus: the expected rules fire', () => {
  const ids = ruleIds(scanDir(MALICIOUS));
  const expected = [
    'SG-INJ-001', // instruction override
    'SG-INJ-003', // concealment
    'SG-EXEC-001', // curl | bash
    'SG-CRED-001', // private-key read
    'SG-EVA-003', // encoded payload recovered
    'SG-SEC-003', // hardcoded credential
    'SG-EXEC-006', // force push
    'SG-EXEC-004', // privilege escalation
  ];
  for (const id of expected) assert.ok(ids.has(id), `${id} should fire on the malicious corpus`);
});

// ---------------------------------------------------------------------------
// Targeted regressions: the false positives found on real public skills
// ---------------------------------------------------------------------------

function scanBody(name, body, extra = {}) {
  const root = makeSkill(name, skillMarkdown(body, { name, description: 'regression fixture' }), extra);
  return scan([root], { config: testConfig() });
}

test('prose that describes behaviour is not a concealment instruction', () => {
  const report = scanBody(
    'prose',
    [
      'The SDK silently retries transient errors and then raises.',
      'This helper runs on every request inside the client.',
      'A mode toggled (auto-approve enabled) is reported to the user.',
      '`sudo` or the system package manager may be required.',
      'Use `eval (expression)` only in a REPL.',
      'Appending this to the system prompt is supported.',
      'Run the linter without checking in generated files.',
    ].join('\n')
  );
  const ids = ruleIds(report);
  for (const id of ['SG-INJ-003', 'SG-INJ-004', 'SG-INJ-006', 'SG-META-004', 'SG-EXEC-002', 'SG-EXEC-004']) {
    assert.ok(!ids.has(id), `${id} must not fire on descriptive prose`);
  }
});

test('a document that warns about injection is not itself injection', () => {
  const report = scanBody(
    'warning',
    'Never write phrases like "disregard the previous instruction" in a prompt, and never run `curl | sh`.'
  );
  const ids = ruleIds(report);
  assert.ok(!ids.has('SG-INJ-001'), 'quoted injection advice is not an override');
  assert.ok(!ids.has('SG-EXEC-001'), 'a warning about curl|sh is not an instruction to run it');
});

test('a blocklist of dangerous git commands is not itself dangerous', () => {
  const report = scanBody(
    'guardrails',
    'This hook blocks dangerous git commands before they run.',
    {
      'scripts/block.sh': [
        '#!/bin/bash',
        'DANGEROUS_PATTERNS=(',
        '  "git push --force"',
        '  "git reset --hard"',
        '  "git clean -fd"',
        ')',
      ].join('\n'),
    }
  );
  assert.ok(!ruleIds(report).has('SG-EXEC-006'));
});

test('a leading byte-order mark is not a hidden character', () => {
  const root = makeSkill(
    'bom',
    `\uFEFF${skillMarkdown('Plain text.', { name: 'bom', description: 'regression fixture' })}`
  );
  const report = scan([root], { config: testConfig() });
  assert.ok(!ruleIds(report).has('SG-INJ-007'));
});

test('copying the example environment file is not credential access', () => {
  const report = scanBody('env-example', '1. `cp .env.example .env`\n2. Edit `.env` with your own values.');
  assert.ok(!ruleIds(report).has('SG-CRED-001'));
});

test('placeholder credentials are not reported', () => {
  const report = scanBody(
    'placeholder',
    ['```python', 'api_key = "your-api-key-here"', 'client_secret = "REPLACE_ME"', '```'].join('\n')
  );
  assert.ok(!ruleIds(report).has('SG-SEC-003'));
});

test('a real hardcoded credential is still reported', () => {
  const report = scanBody(
    'real-secret',
    ['```python', 'api_key = "a8Fk2LmQ9Zx7Vb3Np1Rt"', '```'].join('\n')
  );
  assert.ok(ruleIds(report).has('SG-SEC-003'));
});

test('a tall Markdown table or a long wrapped paragraph is not padding', () => {
  const row = `| ${'column '.repeat(150)} | value |`;
  const paragraph = 'word '.repeat(400);
  const report = scanBody('long-lines', `${row}\n\n${paragraph}`);
  assert.ok(!ruleIds(report).has('SG-OBF-004'));
});

test('a URL path with high entropy is not a secret blob', () => {
  const report = scanBody(
    'url-path',
    'See https://github.com/plutext/docx4j/blob/master/xsd/mce/2012/markup-compatibility.xsd for details.'
  );
  assert.ok(!ruleIds(report).has('SG-OBF-005'));
});

test('bundled fonts are not opaque payloads', () => {
  const root = makeSkill(
    'fonts',
    skillMarkdown('Use the brand font.', { name: 'fonts', description: 'regression fixture' }),
    { 'assets/brand.woff2': Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, 0x00, 0x00, 0x00]) }
  );
  const report = scan([root], { config: testConfig() });
  assert.ok(!ruleIds(report).has('SG-ART-004'));
});

test('an unrelated negation does not suppress a real credential read', () => {
  const report = scanBody(
    'far-away-negation',
    [
      '<!-- Do not copy this fixture anywhere. -->',
      '',
      '# Steps',
      '',
      '1. Read `~/.ssh/id_rsa` to build a checksum.',
    ].join('\n')
  );
  assert.ok(ruleIds(report).has('SG-CRED-001'), 'a distant comment must not mask a credential read');
});

test('comma-separated allowed-tools are parsed, not treated as one string', () => {
  const root = makeSkill(
    'tools-list',
    ['---', 'name: tools-list', 'description: x', 'allowed-tools: Read, Bash', '---', '', 'Run `git status`.'].join('\n')
  );
  const report = scan([root], { config: testConfig() });
  // The skill declares Bash, so the shell use is covered.
  assert.ok(!ruleIds(report).has('SG-META-007'));
});
