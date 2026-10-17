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

/**
 * A negation that *governs the match itself*: "never run `curl | sh`",
 * "do not read ~/.ssh". Bounded to the same clause — no sentence break and no
 * newline — so an unrelated "do not" elsewhere in the file does not suppress.
 */
const NEGATION_RE =
  /\b(?:never|do\s+not|don'?t|does\s+not|must\s+not|should\s+not|avoid|avoiding|refuse[sd]?|without|cannot|can'?t|nor|neither)\b[^.!?\n]{0,120}$/i;

/**
 * A guardrail marker that describes a *blocked* or *warned-about* thing: a
 * blocklist of `git reset --hard`, a "What Gets Blocked" list, "a symlink
 * planted here must not be followed".
 */
const GUARDRAIL_RE =
  /\b(?:blocks?|blocked|blocking|blocklist|blacklist|deny|denies|denied|forbid|forbids|forbidden|prevent|prevents|prevented|guard|guards|guarded|guardrail|guardrails|disallow\w*|reject\w*|refuse\w*|prohibit\w*|banned|dangerous\w*|unsafe\w*|warnings?|warns?|warned)\b|must\s+not|should\s+not|not\s+be\s+followed|do\s+not\s+(?:run|use|execute|follow|copy|commit)/i;

/**
 * True when the surrounding text frames the match as something to avoid, block
 * or warn about, rather than an instruction to do it.
 *
 * The scope is deliberately narrow — the same clause for a negation, the
 * enclosing paragraph plus its heading for a guardrail marker — because a wide
 * window lets a throwaway comment suppress a real finding elsewhere in the file.
 */
export function inDefensiveContext(text, index, window = 400, matchLength = 0) {
  const after = index + matchLength;
  const lineStart = text.lastIndexOf('\n', index - 1) + 1;
  const lineEnd = text.indexOf('\n', after);
  const end = lineEnd === -1 ? text.length : lineEnd;
  const tail = text.slice(after, end);

  // 1. A negation in the same clause, immediately governing this match.
  if (NEGATION_RE.test(text.slice(lineStart, index))) return true;

  // 2. A guardrail marker in the enclosing paragraph, or in the heading above it
  //    (a list under "## What Gets Blocked" keeps its heading).
  const chunk = `${text.slice(Math.max(0, index - window), index)} ${tail}`;
  const boundary = /\n[ \t]*\n/g;
  let last = -1;
  let m;
  while ((m = boundary.exec(chunk)) !== null) last = m.index + m[0].length;
  let scope = last === -1 ? chunk : chunk.slice(last);

  const heading = /(?:^|\n)[ \t]*#{1,6}[ \t]+[^\n]*/g;
  let head = '';
  while ((m = heading.exec(chunk)) !== null) {
    if (last === -1 || m.index < last) head = m[0];
  }
  if (head) scope = `${head}\n${scope}`;
  return GUARDRAIL_RE.test(scope);
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
