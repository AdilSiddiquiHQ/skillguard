import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parseFrontmatter, parseSimpleYaml } from '../src/frontmatter.js';

test('parses scalars, lists and nested maps', () => {
  const data = parseSimpleYaml(
    [
      'name: my-skill',
      'description: "A quoted description"',
      'enabled: true',
      'retries: 3',
      'allowed-tools:',
      '  - Read',
      '  - Bash(git status)',
      'meta:',
      '  author: someone',
      '  version: 2',
      'tags: [alpha, beta, gamma]',
      '# a comment',
      'empty:',
    ].join('\n')
  );

  assert.equal(data.name, 'my-skill');
  assert.equal(data.description, 'A quoted description');
  assert.equal(data.enabled, true);
  assert.equal(data.retries, 3);
  assert.deepEqual(data['allowed-tools'], ['Read', 'Bash(git status)']);
  assert.deepEqual(data.meta, { author: 'someone', version: 2 });
  assert.deepEqual(data.tags, ['alpha', 'beta', 'gamma']);
  assert.deepEqual(data.empty, []);
});

test('extracts frontmatter and leaves the body intact', () => {
  const text = '---\nname: x\ndescription: y\n---\n# Body\n\nHello.';
  const parsed = parseFrontmatter(text);
  assert.equal(parsed.present, true);
  assert.equal(parsed.data.name, 'x');
  assert.equal(parsed.body.trim(), '# Body\n\nHello.');
});

test('handles missing frontmatter gracefully', () => {
  const parsed = parseFrontmatter('# Just a body');
  assert.equal(parsed.present, false);
  assert.equal(parsed.body, '# Just a body');
  assert.deepEqual(parsed.data, {});
});

test('tolerates windows line endings', () => {
  const parsed = parseFrontmatter('---\r\nname: x\r\n---\r\nBody');
  assert.equal(parsed.present, true);
  assert.equal(parsed.data.name, 'x');
});
