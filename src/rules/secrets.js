/**
 * Secret-in-skill rules (OWASP Agentic Skills: AST09).
 * Hardcoded credentials leak into git history, agent transcripts and logs
 * the moment the skill is shared — which is the point of a skill.
 */

import { eachMatch, findingAt } from './helpers.js';
import { shannonEntropy } from '../util.js';

/** Values that are obviously documentation placeholders, not live secrets. */
const PLACEHOLDER =
  /^(?:your|my|the|some|an?|example|sample|test|dummy|fake|placeholder|changeme|change[_-]?me|redacted|todo|fixme|nota?real|x{3,}|\*+|\.+|_{2,}|-{2,}|<[^>]*>|\[[^\]]*\]|\{[^}]*\}|\$\{[^}]*\}|%[sdv]|null|none|undefined|true|false|value|string|secret|password|token|apikey|api[_-]?key|key|abc+|\d+)$/i;

const WORDLIKE = /^[a-z][a-z_-]*$/i;

/** True when `value` looks like a placeholder rather than a real credential. */
export function looksLikePlaceholder(value) {
  const s = String(value).trim();
  if (s.length < 8) return true;
  if (s.includes(' ') || s.includes('\t')) return true;
  if (/\.\.\.|…/.test(s)) return true;
  if (PLACEHOLDER.test(s)) return true;
  if (/\b(?:your|insert|replace|redacted|example|sample|placeholder|here)\b/i.test(s)) return true;
  if (WORDLIKE.test(s)) return true;
  if (!/[A-Za-z]/.test(s)) return true;
  if (/^(?:process\.env|os\.environ|env\.|getenv|import\.meta)/i.test(s)) return true;

  // A real secret mixes character classes or is a long random string.
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(s)).length;
  if (classes >= 3) return false;
  if (s.length >= 20 && shannonEntropy(s) >= 3.4) return false;
  return true;
}

export const secretRules = [
  {
    id: 'SG-SEC-001',
    title: 'Hardcoded API key or access token',
    severity: 'critical',
    confidence: 'high',
    category: 'secrets',
    owasp: 'AST09',
    redact: true,
    description: 'Contains what appears to be a live credential for a well-known provider.',
    remediation: 'Revoke the key immediately, then load it from an environment variable the user provides.',
    patterns: [
      /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
      /\bsk-proj-[A-Za-z0-9_-]{20,}/g,
      /\bsk-[A-Za-z0-9]{32,}/g,
      /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}/g,
      /\bgithub_pat_[A-Za-z0-9_]{30,}/g,
      /\bAKIA[0-9A-Z]{16}\b/g,
      /\bASIA[0-9A-Z]{16}\b/g,
      /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
      /\bAIza[0-9A-Za-z_-]{35}\b/g,
      /\bsk_live_[A-Za-z0-9]{20,}/g,
      /\brk_live_[A-Za-z0-9]{20,}/g,
      /\bglpat-[A-Za-z0-9_-]{20,}/g,
      /\b(?:npm|pypi)_[A-Za-z0-9]{30,}/g,
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    ],
  },
  {
    id: 'SG-SEC-002',
    title: 'Private key material',
    severity: 'critical',
    confidence: 'high',
    category: 'secrets',
    owasp: 'AST09',
    description: 'Contains a private key block. This should never be stored in a skill.',
    remediation: 'Remove the key, rotate it, and reference a path the user controls.',
    patterns: [
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
      /-----BEGIN (?:SSH2 )?ENCRYPTED PRIVATE KEY-----/g,
    ],
  },
  {
    id: 'SG-SEC-003',
    title: 'Hardcoded credential assignment',
    severity: 'high',
    confidence: 'medium',
    category: 'secrets',
    owasp: 'AST09',
    redact: true,
    description: 'Assigns a literal value to a password, secret or token field.',
    remediation: 'Read the value from the environment or a secret manager; never commit it.',
    check(ctx) {
      const re =
        /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*(['"`])([^'"`\n]{6,})\1/gi;
      const out = [];
      for (const { index, match } of eachMatch(re, ctx.text)) {
        if (looksLikePlaceholder(match[2])) continue;
        out.push(findingAt(this, ctx, index, match[0]));
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  {
    id: 'SG-SEC-004',
    title: 'Connection string containing credentials',
    severity: 'critical',
    confidence: 'high',
    category: 'secrets',
    owasp: 'AST09',
    redact: true,
    description: 'A database or broker URL embeds a username and password inline.',
    remediation: 'Move the password to an environment variable and reference it in the URL at runtime.',
    patterns: [
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|clickhouse):\/\/[^:\s/@]+:[^@\s/]+@/gi,
    ],
  },
];
