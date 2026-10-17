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

/** The full line of text containing `index` (no trailing newline). */
export function lineAt(text, index) {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return text.slice(start, end);
}

/**
 * Iterate every match of `pattern`, yielding `{ index, match }`. Always
 * creates a fresh RegExp so callers can safely reuse a shared literal.
 */
export function eachMatch(pattern, text) {
  const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
  const re = new RegExp(pattern.source, flags);
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    out.push({ index: m.index, match: m });
    if (m[0].length === 0) re.lastIndex += 1;
  }
  return out;
}

const DEFENSIVE_RE =
  /\b(?:block|blocks|blocked|blocking|deny|denies|denied|forbid|forbids|forbidden|prevent|prevents|prevented|guard|guards|guarded|guardrail|disallow|disallowed|reject|rejects|rejected|refuse|refuses|refused|dangerous\w*|unsafe\w*|must\s+not|should\s+not|never|do\s+not|don'?t|avoid|warning|warn|instead\s+of|rather\s+than|prohibit\w*|banned|blocklist|blacklist|not\s+(?:be\s+)?follow\w*)\b/i;

/**
 * True when the surrounding text frames the match as something to avoid, block
 * or warn about. A blocklist that quotes `git reset --hard`, or a document
 * that says "never run `curl | sh`", is not an instruction to run it.
 *
 * Both the preceding window and the rest of the current line are examined so
 * that a trailing warning ("... must not be followed") is honoured too.
 */
export function inDefensiveContext(text, index, window = 400, matchLength = 0) {
  const start = Math.max(0, index - window);
  const after = index + matchLength;
  const lineEnd = text.indexOf('\n', after);
  const end = Math.min(text.length, lineEnd === -1 ? text.length : lineEnd);
  return DEFENSIVE_RE.test(`${text.slice(start, index)} ${text.slice(after, end)}`);
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
