import test from 'node:test';
import assert from 'node:assert/strict';

import { compilePolicyRules } from '../src/policy.js';
import { scan } from '../src/scan.js';
import { makeSkill, skillMarkdown, testConfig } from './helpers.js';

test('compiles declarative rules from config', () => {
  const rules = compilePolicyRules({
    rules: [
      { id: 'SG-POLICY-001', title: 'No internal registry', severity: 'high', pattern: 'npm\\.internal\\.' },
      { title: 'No TODO', severity: 'low', pattern: 'TODO' },
    ],
  });
  assert.equal(rules.length, 2);
  assert.equal(rules[0].id, 'SG-POLICY-001');
  assert.equal(rules[0].severity, 'high');
  assert.equal(rules[1].id, 'SG-POLICY-001'.replace('001', '002'));
});

test('skips malformed policy rules without failing', () => {
  const rules = compilePolicyRules({
    rules: [{ title: 'bad regex', pattern: '(' }, { title: 'no pattern' }, null],
  });
  assert.deepEqual(rules, []);
});

test('applies custom policy rules during a scan', () => {
  const root = makeSkill('pol', skillMarkdown('Install from https://npm.internal-artifacts.corp.dev', { name: 'pol', description: 'x' }));
  const config = testConfig({
    policyRules: compilePolicyRules({
      rules: [
        {
          id: 'SG-POLICY-100',
          title: 'Internal registry reference',
          severity: 'critical',
          pattern: 'npm\\.internal-artifacts\\.corp\\.dev',
        },
      ],
    }),
  });
  const report = scan([root], { cwd: root, config });
  const found = report.skills[0].findings.map((f) => f.ruleId);
  assert.ok(found.includes('SG-POLICY-100'));
  assert.equal(report.skills[0].verdict, 'fail');
});

test('severity overrides change the score and verdict', () => {
  const root = makeSkill('sev', skillMarkdown('Run: pkill -f node', { name: 'sev', description: 'x' }));

  const plain = scan([root], { cwd: root, config: testConfig() });
  const hard = scan([root], { cwd: root, config: testConfig({ severityOverrides: { 'SG-EXEC-008': 'critical' } }) });

  assert.ok(hard.skills[0].score >= plain.skills[0].score);
  const overridden = hard.skills[0].findings.find((f) => f.ruleId === 'SG-EXEC-008');
  assert.equal(overridden.severity, 'critical');
  assert.equal(overridden.overridden, true);
});
