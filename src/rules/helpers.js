/**
 * Rule helpers. A rule is plain data:
 *   { id, title, severity, confidence, category, owasp, description,
 *     remediation, patterns?[], check?(ctx) }
 */

import { posAt, redact } from '../util.js';

export function truncate(value, n = 140) {
  const one = String(value).replace(/\s+/g, ' ').trim();
  return one.length > n ? `${one.slice(0, n - 1)}…` : one;
}

export function findingAt(rule, ctx, index, match, extra = {}) {
  const { line, column } = posAt(ctx.lineStarts, index);
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
    file: ctx.file.path,
    line,
    column,
    match: masked,
  };
}

/** Run every regex in `rule.patterns` against the file text. */
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
