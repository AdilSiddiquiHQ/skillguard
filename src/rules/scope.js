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
  {
    id: 'SG-META-007',
    title: 'Body uses a capability the frontmatter does not grant',
    severity: 'high',
    confidence: 'medium',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    perSkill: true,
    description:
      'The skill declares an explicit `allowed-tools` list, but its body performs an action (running a shell, reaching the network, writing files) that the declared list does not cover. The stated permissions do not match the behaviour.',
    remediation:
      'Either grant the tool the skill actually needs, or remove the action from the body. Declared scope should match behaviour.',
    check(ctx) {
      const skill = ctx.skill;
      if (!skill) return [];
      const fm = skill.frontmatter || {};
      const rawTools = fm['allowed-tools'] ?? fm.allowed_tools ?? fm.allowedTools ?? fm.tools;
      if (rawTools === undefined || rawTools === null) return [];
      const granted = new Set(
        (Array.isArray(rawTools) ? rawTools : [rawTools])
          .map((t) => String(t).trim().toLowerCase().replace(/\s*\(.*\)\s*$/, ''))
          .filter(Boolean)
      );
      if (granted.size === 0) return [];
      const hasAny = (...names) => names.some((n) => granted.has(n));

      const body = String(skill.body || '');
      const needs = [];
      if (/\b(?:bash|sh\s+-c|curl|wget|npm\s|pnpm\s|pip3?\s|sudo\s|chmod\s|rm\s+-|git\s)/i.test(body) &&
        !hasAny('bash', 'shell', 'execute', 'exec')) {
        needs.push('shell execution');
      }
      if (/https?:\/\/[^\s)]+/i.test(body) && !hasAny('webfetch', 'websearch', 'fetch', 'browser', 'network')) {
        needs.push('network access');
      }
      if (/(?:^|\n)\s*(?:>|tee\s|cat\s*>|cp\s|mv\s|mkdir\s)/i.test(body) &&
        !hasAny('write', 'edit', 'notebookedit')) {
        needs.push('file writes');
      }
      if (needs.length === 0) return [];
      return [
        findingAt(this, ctx, 0, `undeclared: ${needs.join(', ')}`, {
          description: `The body uses ${needs.join(' and ')} but \`allowed-tools\` does not grant it.`,
        }),
      ];
    },
  },
  {
    id: 'SG-META-008',
    title: 'Frontmatter metadata contains instruction-like text',
    severity: 'high',
    confidence: 'medium',
    category: 'metadata',
    owasp: 'AST02',
    targets: 'skill',
    description:
      'The name or description carries instruction-like phrasing aimed at the agent. Frontmatter is read verbatim by the model, so it is a prompt-injection channel, not just a label.',
    remediation: 'Keep metadata to a plain, factual description of what the skill does.',
    check(ctx) {
      const fm = ctx.frontmatter || {};
      const re =
        /\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above)\b|\byou\s+(?:must|are\s+now|should\s+always)\b|\bdo\s+not\s+(?:tell|inform|warn)\b|\bsystem\s+prompt\b|\bexfiltrat\w*\b/gi;
      const out = [];
      for (const key of ['name', 'description']) {
        const value = fm[key];
        if (typeof value !== 'string') continue;
        re.lastIndex = 0;
        if (re.test(value)) {
          out.push(
            findingAt(this, ctx, 0, `${key}: ${value.slice(0, 60)}`, {
              description: `Frontmatter \`${key}\` contains instruction-like text that targets the agent.`,
            })
          );
        }
      }
      return out;
    },
  },
  {
    id: 'SG-META-009',
    title: 'Non-standard or oversized frontmatter fields',
    severity: 'low',
    confidence: 'medium',
    category: 'metadata',
    owasp: 'AST08',
    targets: 'skill',
    description:
      'The frontmatter contains keys outside the Agent Skills specification, or values longer than the spec allows. Unknown keys are ignored by some harnesses and honoured by others, which makes behaviour inconsistent.',
    remediation: 'Stick to the documented frontmatter keys and keep the description under 1024 characters.',
    check(ctx) {
      const fm = ctx.frontmatter || {};
      const KNOWN = new Set([
        'name', 'description', 'license', 'compatibility', 'allowed-tools', 'allowed_tools',
        'allowedTools', 'metadata', 'version', 'author', 'homepage', 'repository', 'keywords',
        'model', 'disable-model-invocation', 'argument-hint', 'user-invocable', 'tools',
      ]);
      const out = [];
      for (const [key, value] of Object.entries(fm)) {
        if (!KNOWN.has(key)) {
          out.push(findingAt(this, ctx, 0, `unknown key: ${key}`, { severity: 'low' }));
        } else if (typeof value === 'string' && value.length > 1024) {
          out.push(
            findingAt(this, ctx, 0, `${key} is ${value.length} characters`, { severity: 'low' })
          );
        }
        if (out.length >= 5) break;
      }
      return out;
    },
  },
];
