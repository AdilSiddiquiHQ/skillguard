/**
 * Generate docs/RULES.md from the live rule catalog so documentation can
 * never drift from the implementation.
 *
 *   node scripts/generate-rules-doc.js
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { ALL_RULES, CATEGORIES } from '../src/rules/index.js';
import { VERSION } from '../src/version.js';

const OWASP = {
  AST01: 'Malicious or injection-bearing instructions',
  AST02: 'Untrusted dependency or tool instructions',
  AST03: 'Credential and secret access',
  AST04: 'Data exfiltration',
  AST05: 'Unsafe or destructive execution',
  AST06: 'Supply-chain risk',
  AST07: 'Obfuscation',
  AST08: 'Over-broad permissions and metadata hygiene',
  AST09: 'Secret leakage in the skill itself',
  AST10: 'Bundled assets',
};

const out = [];
out.push('# Rule reference');
out.push('');
out.push(
  `SkillSleuth ships **${ALL_RULES.length} rules** across ${CATEGORIES.length} categories. ` +
    'This file is generated from the source by `node scripts/generate-rules-doc.js`.'
);
out.push('');
out.push('## Severity and scoring');
out.push('');
out.push('| Severity | Weight | Typical meaning |');
out.push('|---|---:|---|');
out.push('| critical | 45 | Direct data theft, destructive or deceptive behaviour |');
out.push('| high | 20 | Dangerous capability or clear manipulation |');
out.push('| medium | 8 | Risky pattern that needs review |');
out.push('| low | 3 | Hygiene issue |');
out.push('| info | 0 | Informational only |');
out.push('');
out.push(
  'A skill\'s score is `min(100, Σ weight × confidence)`, where confidence is ' +
    '`high = 1`, `medium = 0.7`, `low = 0.4`. A single critical finding always ' +
    'produces a **FAIL** verdict, and any high or medium finding produces at least **REVIEW**.'
);
out.push('');

for (const category of CATEGORIES) {
  const rules = ALL_RULES.filter((r) => r.category === category);
  if (rules.length === 0) continue;
  out.push(`## ${category} (${rules.length})`);
  out.push('');
  out.push('| Rule | Severity | OWASP | What it detects |');
  out.push('|---|---|---|---|');
  for (const rule of rules) {
    const owasp = rule.owasp ? `${rule.owasp} — ${OWASP[rule.owasp] || ''}` : '—';
    out.push(`| \`${rule.id}\` | ${rule.severity} | ${owasp} | ${rule.title} |`);
  }
  out.push('');
  for (const rule of rules) {
    out.push(`### \`${rule.id}\` — ${rule.title}`);
    out.push('');
    out.push(`**Severity:** ${rule.severity} · **Confidence:** ${rule.confidence} · **Category:** ${rule.category}${rule.owasp ? ` · **OWASP:** ${rule.owasp}` : ''}`);
    out.push('');
    out.push(rule.description);
    out.push('');
    if (rule.remediation) {
      out.push(`**Fix:** ${rule.remediation}`);
      out.push('');
    }
  }
}

out.push('---');
out.push('');
out.push(`_Generated from SkillSleuth v${VERSION}._`);
out.push('');

const target = resolve(import.meta.dirname, '..', 'docs', 'RULES.md');
writeFileSync(target, out.join('\n'), 'utf8');
process.stdout.write(`Wrote ${target} (${ALL_RULES.length} rules)\n`);
