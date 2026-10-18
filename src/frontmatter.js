/**
 * Minimal YAML frontmatter parser for SKILL.md and config files.
 * Supports the subset used by Agent Skills and SkillSleuth config:
 *   key: scalar
 *   key:
 *     - item
 *   key:
 *     nested: value
 *   key: [a, b, c]
 * No dependency, no surprises.
 */

export function parseFrontmatter(text) {
  const result = {
    present: false,
    data: {},
    raw: null,
    body: text,
    bodyOffset: 0,
    error: null,
  };
  const match = /^\uFEFF?---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!match) return result;

  result.present = true;
  result.raw = match[1];
  result.bodyOffset = match[0].length;
  result.body = text.slice(match[0].length);
  try {
    result.data = parseSimpleYaml(match[1]);
  } catch (err) {
    result.error = err && err.message ? err.message : String(err);
  }
  return result;
}

function indentOf(line) {
  return line.length - line.trimStart().length;
}

function parseScalar(raw) {
  const v = String(raw).trim();
  if (v === '') return '';
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  if (v.startsWith('[') && v.endsWith(']')) {
    return splitInlineList(v.slice(1, -1)).map(parseScalar);
  }
  if (v === 'true' || v === 'yes') return true;
  if (v === 'false' || v === 'no') return false;
  if (v === 'null' || v === '~') return null;
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v);
  return v;
}

function splitInlineList(body) {
  const out = [];
  let cur = '';
  let quote = null;
  for (const ch of body) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ',') {
      out.push(cur);
      cur = '';
      continue;
    }
    cur += ch;
  }
  out.push(cur);
  return out.map((x) => x.trim()).filter((x) => x !== '');
}

export function parseSimpleYaml(source) {
  const root = {};
  const lines = String(source).split(/\r?\n/);
  let i = 0;

  while (i < lines.length) {
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      i += 1;
      continue;
    }
    if (indentOf(raw) !== 0) {
      i += 1;
      continue;
    }

    const kv = /^([^:#]+):\s*(.*)$/.exec(trimmed);
    if (!kv) {
      i += 1;
      continue;
    }

    const key = kv[1].trim();
    const rest = kv[2];

    if (rest !== '') {
      root[key] = parseScalar(rest);
      i += 1;
      continue;
    }

    // Block value: gather indented children into a list or map.
    const list = [];
    const map = {};
    let mode = null;
    let baseIndent = null;
    let j = i + 1;

    while (j < lines.length) {
      const child = lines[j];
      if (!child.trim()) {
        j += 1;
        continue;
      }
      const ind = indentOf(child);
      if (ind === 0) break;
      if (baseIndent === null) baseIndent = ind;
      if (ind < baseIndent) break;

      const cTrim = child.trim();
      const listItem = /^-\s*(.*)$/.exec(cTrim);
      if (listItem) {
        mode = 'list';
        list.push(parseScalar(listItem[1]));
      } else {
        const nested = /^([^:#]+):\s*(.*)$/.exec(cTrim);
        if (nested) {
          mode = 'map';
          map[nested[1].trim()] = parseScalar(nested[2]);
        }
      }
      j += 1;
    }

    root[key] = mode === 'map' ? map : list;
    i = j;
  }

  return root;
}
