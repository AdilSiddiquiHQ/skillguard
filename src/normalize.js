/**
 * Deobfuscation and evasion resistance.
 *
 * Published research (Trail of Bits, June 2026) showed that every shipping
 * agent-skill scanner can be bypassed by trivial tricks: prepending 100,000
 * blank lines, hiding payloads in archives, or poisoning compiled artefacts.
 * SkillGuard counters this by scanning several *views* of every file:
 *
 *   raw          the bytes exactly as written
 *   deobfuscated zero-width characters stripped, confusables folded,
 *                NFKC normalised, \uXXXX / &#xNN; escapes decoded
 *   decoded:*    base64 / hex / percent-encoded payloads extracted and scanned
 *   archive:*    entries inside zip / docx / xlsx / pptx / jar containers
 *
 * Character-level transforms keep a per-character index map back to the
 * original text so reported line and column numbers stay truthful.
 */

const ZERO_WIDTH_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u206a-\u206f\ufeff\u00ad\u180e\u061c]/;

/**
 * Common homoglyphs seen in obfuscated skills. Everything is folded to the
 * Latin character it visually impersonates. NFKC already handles the
 * full-width and mathematical-alphanumeric families.
 */
const CONFUSABLES = new Map(
  Object.entries({
    а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', і: 'i', ѕ: 's', ј: 'j',
    ԁ: 'd', һ: 'h', ӏ: 'l', т: 't', м: 'm', н: 'h', ь: 'b', г: 'r', ѵ: 'v', ԛ: 'q',
    κ: 'k', ν: 'v', ρ: 'p', τ: 't', υ: 'u', ο: 'o', α: 'a', ε: 'e', ι: 'i', σ: 'o',
    'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f', 'ɢ': 'g', 'ʜ': 'h',
    'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p',
    'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
  })
);

export function isZeroWidth(ch) {
  return ZERO_WIDTH_RE.test(ch);
}

export function hasZeroWidth(text) {
  return ZERO_WIDTH_RE.test(text);
}

/** Fold a single character to its Latin lookalike, if any. */
export function foldConfusable(ch) {
  return CONFUSABLES.get(ch) || ch;
}

/**
 * Transform `text` character by character, returning the new string plus an
 * array mapping every output index to its source index in `text`.
 * Returning null/undefined from `fn` drops the character.
 */
export function mapTransform(text, fn) {
  let out = '';
  const map = [];
  for (let i = 0; i < text.length; i += 1) {
    const rep = fn(text[i], text, i);
    if (rep === null || rep === undefined) continue;
    const s = String(rep);
    for (let k = 0; k < s.length; k += 1) map.push(i);
    out += s;
  }
  return { text: out, map };
}

const ESCAPE_RE =
  /\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|&#x([0-9a-fA-F]{1,6});|&#([0-9]{1,7});/g;

/**
 * Decode \uXXXX, \u{XXXX}, \xXX and HTML numeric entities, preserving a map
 * back to the original offsets. Percent-encoding is intentionally left to
 * `extractEncodedPayloads` so that ordinary URLs are never rewritten.
 */
export function unescapeWithMap(text) {
  let out = '';
  const map = [];
  let last = 0;
  let raw = '';
  ESCAPE_RE.lastIndex = 0;
  let m;
  while ((m = ESCAPE_RE.exec(text)) !== null) {
    for (let i = last; i < m.index; i += 1) {
      out += text[i];
      map.push(i);
    }
    let cp = null;
    if (m[1]) cp = parseInt(m[1], 16);
    else if (m[2]) cp = parseInt(m[2], 16);
    else if (m[3]) cp = parseInt(m[3], 16);
    else if (m[4]) cp = parseInt(m[4], 16);
    else if (m[5]) cp = parseInt(m[5], 10);

    let rep = m[0];
    if (cp !== null && cp >= 9 && cp <= 0x10ffff) {
      try {
        rep = String.fromCodePoint(cp);
      } catch {
        rep = m[0];
      }
    }
    for (let k = 0; k < rep.length; k += 1) map.push(m.index);
    out += rep;
    last = m.index + m[0].length;
    raw += m[0];
  }
  for (let i = last; i < text.length; i += 1) {
    out += text[i];
    map.push(i);
  }
  return { text: out, map, decoded: raw.length > 0 };
}

/**
 * Produce the canonical deobfuscated view. Returns `{ text, map, tricks }`
 * where `map[i]` is the index in the ORIGINAL text for output character `i`
 * and `tricks` names every obfuscation that was found.
 */
export function deobfuscate(text) {
  const tricks = new Set();

  const pass1 = mapTransform(text, (ch) => {
    if (isZeroWidth(ch)) {
      tricks.add('zero-width');
      return null;
    }
    let c = ch.normalize('NFKC');
    if (c !== ch) tricks.add('unicode-normalisation');
    const folded = foldConfusable(c);
    if (folded !== c) tricks.add('homoglyph');
    return folded;
  });

  const pass2 = unescapeWithMap(pass1.text);
  if (pass2.decoded) tricks.add('escape-sequence');

  const map = pass2.map.map((i) => pass1.map[i] ?? i);
  return { text: pass2.text, map, tricks: [...tricks] };
}

/** ROT13 is included because attackers still use it in "clever" payloads. */
export function rot13(text) {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/** Every distinct zero-width / bidi character in `text`, with a count. */
export function findZeroWidth(text) {
  const found = new Map();
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (isZeroWidth(ch)) found.set(ch, (found.get(ch) || 0) + 1);
  }
  return [...found.entries()].map(([ch, count]) => ({
    char: ch,
    codePoint: `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
    count,
  }));
}

/** Homoglyph characters that impersonate ASCII, with positions. */
export function findConfusables(text, limit = 40) {
  const out = [];
  for (let i = 0; i < text.length && out.length < limit; i += 1) {
    const ch = text[i];
    const folded = foldConfusable(ch.normalize('NFKC'));
    if (folded !== ch && /^[a-z]$/i.test(folded)) {
      out.push({ index: i, char: ch, looksLike: folded });
    }
  }
  return out;
}

/**
 * Detect padding / flood attacks: the documented ClawHub bypass prepends
 * 100,000 blank lines so the scanner's context is spent before the payload.
 */
export function detectPadding(text) {
  if (!text) return [];

  // Runs of consecutive newlines.
  const runs = text.match(/\n{50,}/g);
  const results = [];
  if (runs && runs.length > 0) {
    const longest = runs.reduce((a, b) => (b.length > a.length ? b : a));
    const index = text.indexOf(longest);
    const line = text.slice(0, index).split('\n').length;
    results.push({ kind: 'blank-lines', count: longest.length - 1, line });
  }

  // A single enormous line is the other classic truncation bait.
  let line = 0;
  let start = 0;
  for (let i = 0; i <= text.length; i += 1) {
    if (i === text.length || text.charCodeAt(i) === 10) {
      const len = i - start;
      if (len >= 20000) {
        results.push({ kind: 'long-line', count: len, line: line + 1 });
      }
      line += 1;
      start = i + 1;
    }
  }

  return results;
}

function printableRatio(str) {
  if (!str) return 0;
  let printable = 0;
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) printable += 1;
  }
  return printable / str.length;
}

export { printableRatio };

const BASE64_RE = /[A-Za-z0-9+/]{32,}={0,2}/g;
const HEX_RE = /(?<![0-9a-zA-Z])[0-9a-fA-F]{32,}(?![0-9a-zA-Z])/g;
const PERCENT_RE = /(?:%[0-9a-fA-F]{2}){8,}/g;

function looksBase64(s) {
  if (!/[A-Z]/.test(s) || !/[a-z]/.test(s) || !/[0-9+/=]/.test(s)) return false;
  const padding = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  return (s.length - padding) % 4 === 0 || s.length % 4 === 0;
}

/**
 * Extract and decode embedded payloads. Only blobs that decode to mostly
 * printable text and contain letters are returned, which keeps ordinary
 * hashes and identifiers from creating noise.
 *
 * Returns `[{ encoding, raw, decoded, index, layers }]`.
 */
export function extractEncodedPayloads(text, options = {}) {
  const minPrintable = options.minPrintable ?? 0.85;
  const maxPayloads = options.maxPayloads ?? 8;
  const maxBytes = options.maxBytes ?? 256 * 1024;
  const out = [];
  const seen = new Set();

  const push = (encoding, raw, decoded, index) => {
    if (out.length >= maxPayloads) return;
    if (decoded.length > maxBytes) return;
    if (!/[a-zA-Z]{4}/.test(decoded)) return;
    if (printableRatio(decoded) < minPrintable) return;
    const key = `${encoding}:${decoded.slice(0, 64)}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ encoding, raw, decoded, index, layers: 1 });
  };

  for (const m of text.matchAll(BASE64_RE)) {
    if (!looksBase64(m[0])) continue;
    try {
      const decoded = Buffer.from(m[0], 'base64').toString('utf8');
      push('base64', m[0], decoded, m.index);
    } catch {
      /* ignore */
    }
  }

  for (const m of text.matchAll(HEX_RE)) {
    if (m[0].length % 2 !== 0) continue;
    try {
      const decoded = Buffer.from(m[0], 'hex').toString('utf8');
      push('hex', m[0], decoded, m.index);
    } catch {
      /* ignore */
    }
  }

  for (const m of text.matchAll(PERCENT_RE)) {
    try {
      const decoded = decodeURIComponent(m[0]);
      push('percent-encoding', m[0], decoded, m.index);
    } catch {
      /* ignore */
    }
  }

  // One extra layer: payloads hidden inside payloads.
  const nested = [];
  for (const payload of out) {
    if (payload.layers >= 2) continue;
    for (const inner of extractEncodedPayloads(payload.decoded, { ...options, maxPayloads: 2 })) {
      nested.push({ ...inner, layers: payload.layers + 1, parent: payload.encoding });
    }
  }

  return [...out, ...nested].slice(0, maxPayloads);
}
