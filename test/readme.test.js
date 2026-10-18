/**
 * The README shows real command output. Output that no longer matches the tool
 * is the most common form of README rot, and for a scanner it is worse than
 * rot: a reader who runs the command and gets different numbers stops trusting
 * every other number in the file.
 *
 * This test scans the shipped fixtures and asserts that the exact summary line
 * the tool would print is present in the README.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { test } from 'node:test';

import { scan } from '../src/scan.js';
import { pluralize } from '../src/util.js';
import { testConfig } from './helpers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const README = readFileSync(join(ROOT, 'README.md'), 'utf8');

/** The summary line the terminal reporter prints, without colour. */
function summaryLine(report) {
  const s = report.summary;
  const counts = s.counts;
  const info = counts.info ? ` ${counts.info} info` : '';
  return (
    `${pluralize(s.skills, 'skill')} · ${pluralize(s.findings, 'finding')} · ` +
    `${counts.critical} critical ${counts.high} high ${counts.medium} medium ${counts.low} low${info}`
  );
}

const normalize = (text) => text.replace(/\s+/g, ' ');

const DEMOS = ['examples/evasion', 'examples/cleanup-trap', 'examples/conventional-commit'];

test('every README demo summary matches the tool', () => {
  const readme = normalize(README);
  for (const dir of DEMOS) {
    const report = scan([join(ROOT, dir)], { cwd: HERE, config: testConfig() });
    assert.ok(report.skills.length > 0, `${dir} must contain at least one scannable skill`);
    const line = normalize(summaryLine(report));
    assert.ok(
      readme.includes(line),
      `README is stale for ${dir}: it must contain "${line}"`
    );
    const header = `SkillSleuth ${report.version} · ${report.ruleCount} rules · agent skills security scanner`;
    assert.ok(
      readme.includes(header),
      `README is stale: the demo blocks must show the current header "${header}"`
    );
  }
});
