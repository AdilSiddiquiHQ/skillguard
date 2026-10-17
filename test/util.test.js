import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildLineStarts,
  countBySeverity,
  globToRegExp,
  isAtLeast,
  looksBinary,
  matchesAny,
  posAt,
  redact,
  severityRank,
  shannonEntropy,
} from '../src/util.js';
import { scoreFindings, verdictFor } from '../src/score.js';

test('severity ranking orders critical above info', () => {
  assert.ok(severityRank('critical') < severityRank('high'));
  assert.ok(severityRank('high') < severityRank('low'));
  assert.ok(isAtLeast('critical', 'high'));
  assert.ok(!isAtLeast('low', 'high'));
  assert.ok(!isAtLeast('critical', 'none'));
});

test('computes line and column from an index', () => {
  const text = 'one\ntwo\nthree';
  const starts = buildLineStarts(text);
  assert.deepEqual(posAt(starts, 0), { line: 1, column: 1 });
  assert.deepEqual(posAt(starts, 4), { line: 2, column: 1 });
  assert.deepEqual(posAt(starts, 5), { line: 2, column: 2 });
  assert.deepEqual(posAt(starts, 8), { line: 3, column: 1 });
  assert.deepEqual(posAt(starts, 9), { line: 3, column: 2 });
});

test('glob matching handles wildcards and parent directories', () => {
  const res = [globToRegExp('**/node_modules/**'), globToRegExp('examples/trap')];
  assert.ok(matchesAny('examples/trap', res));
  assert.ok(matchesAny('examples/trap/SKILL.md', res));
  assert.ok(matchesAny('a/b/node_modules/c/d.js', res));
  assert.ok(!matchesAny('examples/clean/SKILL.md', res));
});

test('redaction hides the middle of a secret', () => {
  const value = 'sk-ant-abcdefghijklmnop';
  const masked = redact(value);
  assert.ok(masked.startsWith('sk-a'));
  assert.ok(masked.endsWith('op'));
  assert.ok(!masked.includes('defghijklmn'));
});

test('entropy distinguishes random from repetitive strings', () => {
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaaa') < 1);
  assert.ok(shannonEntropy('9f8a7b6c5d4e3f2a1b0c') > 3.5);
});

test('binary detection catches NUL bytes', () => {
  assert.ok(looksBinary('hello\u0000world'));
  assert.ok(!looksBinary('hello world'));
});

test('scoring weights severity and confidence', () => {
  assert.equal(scoreFindings([]), 0);
  assert.equal(scoreFindings([{ severity: 'critical', confidence: 'high' }]), 45);
  assert.equal(scoreFindings([{ severity: 'high', confidence: 'medium' }]), 14);
  assert.equal(
    scoreFindings([
      { severity: 'critical', confidence: 'high' },
      { severity: 'critical', confidence: 'high' },
      { severity: 'critical', confidence: 'high' },
    ]),
    100
  );
});

test('verdict thresholds are applied', () => {
  assert.equal(verdictFor(0), 'pass');
  assert.equal(verdictFor(29), 'pass');
  assert.equal(verdictFor(30), 'review');
  assert.equal(verdictFor(69), 'review');
  assert.equal(verdictFor(70), 'fail');
  assert.equal(verdictFor(100), 'fail');
});

test('severity alone can force review or fail regardless of score', () => {
  assert.equal(verdictFor(0, undefined, [{ severity: 'critical' }]), 'fail');
  assert.equal(verdictFor(0, undefined, [{ severity: 'high' }]), 'review');
  assert.equal(verdictFor(0, undefined, [{ severity: 'medium' }]), 'review');
  assert.equal(verdictFor(0, undefined, [{ severity: 'low' }]), 'pass');
  assert.equal(verdictFor(0, undefined, [{ severity: 'info' }]), 'pass');
});

test('counts findings by severity', () => {
  const counts = countBySeverity([
    { severity: 'critical' },
    { severity: 'critical' },
    { severity: 'low' },
    { severity: 'info' },
  ]);
  assert.deepEqual(counts, { critical: 2, high: 0, medium: 0, low: 1, info: 1 });
});
