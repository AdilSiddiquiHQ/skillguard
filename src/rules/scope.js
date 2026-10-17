/**
 * Metadata and scope hygiene rules (OWASP Agentic Skills: AST08).
 * Over-broad declared permissions are how a skill gets more access than
 * the user intended to grant.
 */

import { findingAt } from './helpers.js';

const PERMISSION_KEYS = [
  'allowed-tools',
  'allowed_tools',
  'allowedTools',
  'tools',
  'permissions',
  'permission',
  'capabilities',
  'scopes',
  'scope',
];

const SCOPE_KEYS = ['network', 'shell', 'filesystem', 'file-system', 'fs', 'exec', 'execute'];

export const scopeRules = [
  {
    id: 'SG-META-001',
    title: 'Missing skill description',
    severity: 'low',
    confidence: 'high',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    description:
      'The SKILL.md has no description in frontmatter, so the agent cannot judge when the skill applies and the user cannot judge intent.',
    remediation: 'Add a `description` in frontmatter that states exactly what the skill does and when it triggers.',
    check(ctx) {
      if (!ctx.frontmatterPresent) return [];
      const desc = ctx.frontmatter.description;
      if (typeof desc === 'string' && desc.trim()) return [];
      return [findingAt(this, ctx, 0, 'no description in frontmatter')];
    },
  },
  {
    id: 'SG-META-002',
    title: 'Wildcard or unrestricted tool grants',
    severity: 'high',
    confidence: 'high',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    description:
      'Frontmatter requests wildcard permissions (for example `allowed-tools: *`), granting the skill far more capability than it needs.',
    remediation: 'List only the specific tools the skill uses, with the narrowest scopes you can.',
    check(ctx) {
      const out = [];
      const fm = ctx.frontmatter || {};
      for (const key of PERMISSION_KEYS) {
        const value = fm[key];
        if (value === undefined || value === null) continue;
        const values = Array.isArray(value) ? value : [value];
        for (const val of values) {
          const s = String(val).trim().toLowerCase();
          if (!s) continue;
          if (s === '*' || s === '**' || s === 'all' || s === 'any' || s === 'unrestricted') {
            out.push(findingAt(this, ctx, 0, `${key}: ${val}`));
          } else if (s.includes('*')) {
            out.push(
              findingAt(this, ctx, 0, `${key}: ${val}`, {
                severity: 'medium',
                description: `Frontmatter grants a scoped wildcard in \`${key}\` (${val}), which still allows more than the skill needs.`,
              })
            );
          }
        }
      }
      return out;
    },
  },
  {
    id: 'SG-META-003',
    title: 'Declares broad runtime scope',
    severity: 'medium',
    confidence: 'medium',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    description: 'Frontmatter declares broad network, shell or filesystem access at the root or for everything.',
    remediation: 'Narrow the declared scope, or drop the declaration if the skill does not need it.',
    check(ctx) {
      const out = [];
      const fm = ctx.frontmatter || {};
      for (const key of SCOPE_KEYS) {
        const value = fm[key];
        if (value === undefined || value === null) continue;
        const values = Array.isArray(value) ? value : [value];
        for (const val of values) {
          const s = String(val).trim().toLowerCase();
          const broad =
            val === true ||
            s === '*' || s === 'all' || s === 'any' || s === '/' || s === '**' || s === 'true' ||
            s.startsWith('/') || s.includes('0.0.0.0');
          if (broad) out.push(findingAt(this, ctx, 0, `${key}: ${val}`));
        }
      }
      return out;
    },
  },
  {
    id: 'SG-META-004',
    title: 'Skill claims to always run or auto-apply',
    severity: 'medium',
    confidence: 'medium',
    category: 'metadata',
    owasp: 'AST08',
    description:
      'Claims to run on every task or always take effect, which makes the skill permanently active beyond the user\'s intent.',
    remediation: 'Make the skill apply only when its trigger conditions are clearly met.',
    patterns: [
      /\balways\s+(?:use|run|apply|invoke|execute|load)\s+this\s+skill\b/gi,
      /\b(?:on|for)\s+every\s+(?:task|prompt|request|message|conversation|interaction)\b/gi,
      /\b(?:before|after)\s+(?:every|any|all)\s+(?:response|answer|reply|task)\b/gi,
      /\balways\s+active\b|\bpermanently\s+enabled\b/gi,
    ],
  },
  {
    id: 'SG-META-005',
    title: 'Skill has no frontmatter',
    severity: 'low',
    confidence: 'high',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    description:
      'The SKILL.md has no frontmatter block, so it cannot declare a name, description or scoped permissions.',
    remediation: 'Add a frontmatter block with at least `name` and `description`.',
    check(ctx) {
      if (ctx.frontmatterPresent) return [];
      return [findingAt(this, ctx, 0, 'missing frontmatter')];
    },
  },
  {
    id: 'SG-META-006',
    title: 'Skill name does not match its directory',
    severity: 'low',
    confidence: 'medium',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    description:
      'The declared name differs from the folder name, which makes review and pinning harder.',
    remediation: 'Keep the frontmatter `name` identical to the directory name.',
    check(ctx) {
      const name = ctx.frontmatter && ctx.frontmatter.name;
      if (typeof name !== 'string' || !name.trim()) return [];
      if (!ctx.skill || !ctx.skill.relDir) return [];
      const dirName = ctx.skill.relDir.split('/').pop();
      if (!dirName || dirName === '.') return [];
      if (name.trim().toLowerCase() === dirName.toLowerCase()) return [];
      return [findingAt(this, ctx, 0, `name "${name}" vs folder "${dirName}"`)];
    },
  },
];
