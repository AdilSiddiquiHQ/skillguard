/**
 * Rule helpers. A rule is plain data:
 *   { id, title, severity, confidence, category, owasp, description,
 *     remediation, patterns?[], check?(ctx), views?[], perSkill? }
 *
 * `views` restricts which scan views a rule sees: 'raw', 'deobfuscated',
 * 'decoded' or 'archive'. Omit it for every view.
 */

import { posAt, redact } from '../util.js';

export function truncate(value, n = 140) {
  const one = String(value).replace(/\s+/g, ' ').trim();
  return one.length > n ? `${one.slice(0, n - 1)}…` : one;
}

export function findingAt(rule, ctx, index, match, extra = {}) {
  const pos = ctx.posFor ? ctx.posFor(index) : posAt(ctx.lineStarts, index);
  const masked = rule.redact ? redact(match) : truncate(match);
  return {
    ruleId: rule.id,
    title: rule.title,
    severity: extra.severity || rule.severity,
    confidence: extra.confidence || rule.confidence || 'medium',
    category: rule.category,
    owasp: rule.owasp || null,
    description: extra.description || rule.description,
    remediation: rule.remediation || '',
    file: extra.file || ctx.fileLabel || (ctx.file && ctx.file.path) || '(unknown)',
    line: pos.line,
    column: pos.column,
    match: masked,
    evasion: extra.evasion !== undefined ? extra.evasion : ctx.evasion || null,
    derivedFrom: extra.derivedFrom !== undefined ? extra.derivedFrom : ctx.derivedFrom || null,
  };
}

/** Run every regex in `rule.patterns` against the current view text. */
export function runPatterns(rule, ctx, maxPerRule) {
  const findings = [];
  const { text } = ctx;

  for (const pattern of rule.patterns) {
    const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
    const re = new RegExp(pattern.source, flags);
    let match;
    while ((match = re.exec(text)) !== null) {
      findings.push(findingAt(rule, ctx, match.index, match[0]));
      if (match[0].length === 0) re.lastIndex += 1;
      if (findings.length >= maxPerRule) return findings;
    }
  }

  return findings;
}
