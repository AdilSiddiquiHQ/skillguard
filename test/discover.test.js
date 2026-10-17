import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { classifySpecial, discoverSkills } from '../src/discover.js';

function workspace() {
  return mkdtempSync(join(tmpdir(), 'skillguard-discover-'));
}

function write(root, rel, content) {
  const target = join(root, rel);
  mkdirSync(join(target, '..'), { recursive: true });
  writeFileSync(target, content, 'utf8');
}

test('classifies the adjacent agent surfaces', () => {
  assert.equal(classifySpecial('.mcp.json'), 'mcp');
  assert.equal(classifySpecial('config/claude_desktop_config.json'), 'mcp');
  assert.equal(classifySpecial('.claude-plugin/plugin.json'), 'plugin');
  assert.equal(classifySpecial('CLAUDE.md'), 'agents');
  assert.equal(classifySpecial('.cursor/rules/style.mdc'), 'agents');
  assert.equal(classifySpecial('src/index.js'), null);
});

test('discovers skills, plugins, MCP configs and agent files together', () => {
  const root = workspace();
  write(root, 'skills/format/SKILL.md', '---\nname: format\ndescription: format code\n---\n\nbody\n');
  write(root, '.claude-plugin/plugin.json', JSON.stringify({ name: 'p' }));
  write(root, '.mcp.json', JSON.stringify({ mcpServers: {} }));
  write(root, 'CLAUDE.md', '# Project rules\n');
  write(root, '.cursor/rules/style.mdc', '---\ndescription: style\n---\n\nrules\n');

  const targets = discoverSkills(['.'], { cwd: root });
  const kinds = targets.map((t) => t.kind).sort();
  assert.deepEqual(kinds, ['agents', 'agents', 'mcp', 'plugin', 'skill']);
});

test('hidden files are scanned, not skipped', () => {
  const root = workspace();
  write(root, 'skills/s/SKILL.md', '---\nname: s\ndescription: s\n---\n\nx\n');
  write(root, 'skills/s/.hidden-config.json', JSON.stringify({ note: 'api_key = "AKIAIOSFODNN7EXAMPLE"' }));

  const targets = discoverSkills(['.'], { cwd: root });
  const skill = targets.find((t) => t.kind === 'skill');
  assert.ok(
    skill.files.some((f) => f.path.endsWith('.hidden-config.json')),
    'hidden files inside a skill must be included'
  );
});

test('does not descend into a nested skill as plain files', () => {
  const root = workspace();
  write(root, 'a/SKILL.md', '---\nname: a\ndescription: a\n---\n\nx\n');
  write(root, 'a/nested/SKILL.md', '---\nname: nested\ndescription: nested\n---\n\ny\n');

  const targets = discoverSkills(['.'], { cwd: root }).filter((t) => t.kind === 'skill');
  assert.equal(targets.length, 2);
  assert.ok(targets.every((t) => !t.files.some((f) => f.path.includes('nested/SKILL.md') && t.name !== 'nested')));
});
