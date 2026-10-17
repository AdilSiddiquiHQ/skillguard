/**
 * Shared helpers: severity handling, hashing, entropy, unicode and glob utilities.
 * Zero dependencies on purpose — every line is auditable.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { sep } from 'node:path';

/** Ordered from most to least severe. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/** Weight each severity contributes to the 0-100 risk score. */
export const SEVERITY_WEIGHT = {
  critical: 45,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
};

/** Multiplier applied by finding confidence. */
export const CONFIDENCE_FACTOR = {
  high: 1,
  medium: 0.7,
  low: 0.4,
};

export function severityRank(severity) {
  const i = SEVERITIES.indexOf(severity);
  return i === -1 ? SEVERITIES.length : i;
}

export function compareSeverity(a, b) {
  return severityRank(a) - severityRank(b);
}

/** True when `severity` is at least as severe as `threshold`. */
export function isAtLeast(severity, threshold) {
  if (!threshold || threshold === 'none') return false;
  return severityRank(severity) <= severityRank(threshold);
}

export function sha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

export function buildLineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

export function posAt(lineStarts, index) {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: index - lineStarts[lo] + 1 };
}

/** Shannon entropy in bits per character. */
export function shannonEntropy(str) {
  if (!str) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Keep a hint of the value but never echo a full secret. */
export function redact(value) {
  const s = String(value);
  if (s.length <= 8) return '*'.repeat(s.length);
  return `${s.slice(0, 4)}${'*'.repeat(Math.min(12, s.length - 6))}${s.slice(-2)}`;
}

export function toPosix(p) {
  return p.split(sep).join('/');
}

/** Tiny glob -> RegExp supporting `**`, `*` and `?`. */
export function globToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i += 1) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i += 1;
        if (glob[i + 1] === '/') i += 1;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if ('\\^$+.()|{}[]'.includes(c)) {
      re += `\\${c}`;
    } else {
      re += c;
    }
  }
  return new RegExp(`^${re}$`);
}

/**
 * Match a path against any pattern. Also matches parent directories so that
 * excluding a folder excludes everything beneath it.
 */
export function matchesAny(relPath, regexes) {
  const parts = toPosix(relPath).split('/');
  for (const re of regexes) {
    for (let i = 1; i <= parts.length; i += 1) {
      if (re.test(parts.slice(0, i).join('/'))) return true;
    }
  }
  return false;
}

export function readTextFileSafe(path) {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

export function readFileBufferSafe(path) {
  try {
    return readFileSync(path);
  } catch {
    return null;
  }
}

export function sha256Buffer(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** Hex of the first bytes of a file, used for magic-number detection. */
export function readFileMagic(path, length = 8) {
  const buf = readFileBufferSafe(path);
  if (!buf) return null;
  return buf.subarray(0, length).toString('hex');
}

/** Heuristic binary detection using NUL bytes and control-character density. */
export function looksBinary(text) {
  if (text.includes('\u0000')) return true;
  const sample = text.slice(0, 4096);
  if (!sample) return false;
  let control = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const code = sample.charCodeAt(i);
    if (code < 9 || (code > 13 && code < 32)) control += 1;
  }
  return control / sample.length > 0.1;
}

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }
  return counts;
}

export function pluralize(n, singular, plural = `${singular}s`) {
  return `${n} ${n === 1 ? singular : plural}`;
}
