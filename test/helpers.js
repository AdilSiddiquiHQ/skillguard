import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { DEFAULT_CONFIG } from '../src/config.js';

/** Create a throwaway skill directory containing SKILL.md plus extra files. */
export function makeSkill(name, content, extra = {}) {
  const root = mkdtempSync(join(tmpdir(), 'skillsleuth-'));
  const skillDir = join(root, name);
  mkdirSync(skillDir, { recursive: true });
  writeFileSync(join(skillDir, 'SKILL.md'), content, 'utf8');

  for (const [rel, body] of Object.entries(extra)) {
    const target = join(skillDir, rel);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, body);
  }

  return root;
}

export function skillMarkdown(body, frontmatter = {}) {
  const lines = ['---'];
  for (const [key, value] of Object.entries(frontmatter)) {
    lines.push(`${key}: ${value}`);
  }
  lines.push('---', '');
  lines.push(body);
  return lines.join('\n');
}

export function testConfig(overrides = {}) {
  return {
    ...DEFAULT_CONFIG,
    thresholds: { ...DEFAULT_CONFIG.thresholds },
    ...overrides,
  };
}

export function ruleIds(report) {
  return report.skills.flatMap((s) => s.findings.map((f) => f.ruleId));
}
