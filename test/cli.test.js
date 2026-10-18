import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseArgs } from '../src/cli.js';

test('defaults to no paths and sensible flags', () => {
  const flags = parseArgs([]);
  assert.deepEqual(flags.paths, []);
  assert.equal(flags.failOn, null);
  assert.equal(flags.error, null);
});

test('collects positional paths', () => {
  const flags = parseArgs(['a', 'b/c', '--json']);
  assert.deepEqual(flags.paths, ['a', 'b/c']);
  assert.equal(flags.json, true);
});

test('parses value flags with space and equals', () => {
  const spaced = parseArgs(['--fail-on', 'critical']);
  assert.equal(spaced.failOn, 'critical');

  const equals = parseArgs(['--fail-on=medium', '--min-score=42']);
  assert.equal(equals.failOn, 'medium');
  assert.equal(equals.minScore, 42);
});

test('optional-value flags fall back to defaults', () => {
  const bare = parseArgs(['--sarif']);
  assert.equal(bare.sarif, 'skillsleuth.sarif');

  const named = parseArgs(['--sarif', 'out.sarif']);
  assert.equal(named.sarif, 'out.sarif');
});

test('repeatable flags accumulate', () => {
  const flags = parseArgs(['--ignore', 'SG-A-1,SG-A-2', '--ignore', 'SG-B-1', '--exclude', 'x/**', '--exclude', 'y/**']);
  assert.deepEqual(flags.ignore, ['SG-A-1', 'SG-A-2', 'SG-B-1']);
  assert.deepEqual(flags.exclude, ['x/**', 'y/**']);
});

test('rejects invalid severities and scores', () => {
  assert.match(parseArgs(['--fail-on', 'banana']).error, /Invalid --fail-on/);
  assert.match(parseArgs(['--min-score', '999']).error, /Invalid --min-score/);
});

test('rejects unknown options and missing values', () => {
  assert.match(parseArgs(['--nope']).error, /Unknown option/);
  assert.match(parseArgs(['--config']).error, /requires a value/);
});

test('double dash stops option parsing', () => {
  const flags = parseArgs(['--', '--not-a-flag']);
  assert.deepEqual(flags.paths, ['--not-a-flag']);
});
