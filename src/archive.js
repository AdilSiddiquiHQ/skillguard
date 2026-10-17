/**
 * Container and compiled-artefact inspection.
 *
 * Two of the four documented scanner bypasses relied on content the static
 * analysers never opened: a malicious shell script smuggled inside a `.docx`
 * (which is just a ZIP of XML) and a poisoned `.pyc` that disagreed with the
 * Python source beside it. SkillGuard opens both.
 *
 * The ZIP reader is intentionally small: central-directory driven, inflated
 * with `node:zlib`, and hard-guarded against zip bombs.
 */

import { inflateRawSync } from 'node:zlib';

import { readFileBufferSafe } from './util.js';

export const ARCHIVE_EXTENSIONS = new Set([
  '.zip', '.docx', '.xlsx', '.pptx', '.jar', '.war', '.vsix', '.odt', '.ods',
  '.epub', '.apk', '.xpi', '.egg', '.whl', '.nupkg',
]);

export const BINARY_ARTIFACT_EXTENSIONS = new Set([
  '.pyc', '.pyo', '.so', '.dll', '.dylib', '.node', '.wasm', '.class', '.exe',
  '.bin', '.o', '.a', '.ko', '.elf', '.com', '.scr', '.msixbundle',
]);

export const TEXT_ENTRY_EXTENSIONS = new Set([
  '.xml', '.txt', '.md', '.markdown', '.json', '.yaml', '.yml', '.sh', '.bash',
  '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.py', '.js', '.mjs', '.cjs', '.ts',
  '.rb', '.pl', '.php', '.html', '.htm', '.csv', '.ini', '.cfg', '.conf', '.jsx',
  '.properties', '.rels', '.toml',
]);

const EOCD_SIG = 0x06054b50;
const CDH_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;

const LIMITS = {
  maxEntries: 1024,
  maxSingleBytes: 4 * 1024 * 1024,
  maxTotalBytes: 24 * 1024 * 1024,
  maxRatio: 500,
  maxDepth: 2,
};

export function extensionOf(name) {
  const base = String(name).toLowerCase().split('/').pop();
  const dot = base.lastIndexOf('.');
  return dot === -1 ? '' : base.slice(dot);
}

export function isArchivePath(name) {
  return ARCHIVE_EXTENSIONS.has(extensionOf(name));
}

export function isBinaryArtifactPath(name) {
  return BINARY_ARTIFACT_EXTENSIONS.has(extensionOf(name));
}

/** Locate the End Of Central Directory record. */
function findEocd(buf) {
  const min = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  return -1;
}

/**
 * Parse a ZIP buffer into entries. Returns `[]` for anything malformed, so a
 * corrupt file can never crash the scan.
 */
export function readZip(buf, depth = 0) {
  if (!buf || buf.length < 22) return [];
  const eocd = findEocd(buf);
  if (eocd === -1) return [];

  const total = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  const entries = [];
  let totalBytes = 0;

  for (let i = 0; i < total && i < LIMITS.maxEntries; i += 1) {
    if (offset + 46 > buf.length || buf.readUInt32LE(offset) !== CDH_SIG) break;

    const method = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const uncompressedSize = buf.readUInt32LE(offset + 24);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localOffset = buf.readUInt32LE(offset + 42);
    const name = buf.toString('utf8', offset + 46, offset + 46 + nameLen);

    offset += 46 + nameLen + extraLen + commentLen;

    // Skip directories, zip64 markers and encrypted entries.
    if (name.endsWith('/')) continue;
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff) continue;
    if (uncompressedSize > LIMITS.maxSingleBytes) continue;
    if (totalBytes + uncompressedSize > LIMITS.maxTotalBytes) break;

    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== LFH_SIG) continue;
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > buf.length) continue;

    let data = null;
    try {
      if (method === 0) {
        data = buf.subarray(dataStart, dataEnd);
      } else if (method === 8) {
        const ratio = compressedSize === 0 ? Infinity : uncompressedSize / compressedSize;
        if (ratio > LIMITS.maxRatio && uncompressedSize > 1024 * 1024) continue;
        data = inflateRawSync(buf.subarray(dataStart, dataEnd));
      } else {
        continue;
      }
    } catch {
      continue;
    }

    totalBytes += data.length;
    entries.push({ name, data: Buffer.from(data), bytes: data.length, depth });
  }

  return entries;
}

/** True when a buffer looks like a ZIP container. */
export function looksLikeZip(buf) {
  return Boolean(buf && buf.length >= 4 && buf.readUInt32LE(0) === LFH_SIG);
}

function isTextyName(name) {
  return TEXT_ENTRY_EXTENSIONS.has(extensionOf(name));
}

function decodeEntry(entry) {
  if (entry.data.includes(0)) return null;
  const text = entry.data.toString('utf8');
  if (!text) return null;
  const sample = text.slice(0, 4096);
  let control = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const code = sample.charCodeAt(i);
    if (code < 9 || (code > 13 && code < 32)) control += 1;
  }
  if (control / sample.length > 0.1) return null;
  return text;
}

/**
 * Open a container and return scannable text entries. Office documents are
 * fully traversed, including the XML that carries their real instructions.
 */
export function extractArchive(buf, options = {}) {
  const depth = options.depth || 0;
  const out = [];
  const entries = readZip(buf, depth);

  for (const entry of entries) {
    if (out.length >= (options.maxEntries || 256)) break;

    const nestedZip = looksLikeZip(entry.data) && depth < LIMITS.maxDepth;
    if (nestedZip) {
      for (const inner of extractArchive(entry.data, { ...options, depth: depth + 1 })) {
        out.push({ ...inner, name: `${entry.name}!${inner.name}` });
      }
      continue;
    }

    const text = decodeEntry(entry);
    if (text === null) {
      out.push({ name: entry.name, text: null, bytes: entry.bytes, binary: true });
      continue;
    }
    if (!isTextyName(entry.name) && text.length < 24) continue;
    out.push({ name: entry.name, text, bytes: entry.bytes, binary: false });
  }

  return out;
}

/** Load and open an archive from disk. Never throws. */
export function readArchiveFile(path, options = {}) {
  const buf = readFileBufferSafe(path);
  if (!buf) return [];
  return extractArchive(buf, options);
}

/**
 * Pull printable strings out of a binary so patterns can still match inside
 * compiled artefacts (`LD_PRELOAD`, embedded `curl | sh`, base64 blobs).
 */
export function extractStrings(buf, options = {}) {
  const minLen = options.minLen || 5;
  const maxBytes = options.maxBytes || 512 * 1024;
  const found = [];

  if (!buf) return found;

  // ASCII / UTF-8 runs.
  const ascii = buf.toString('latin1');
  const re = new RegExp(`[\\x20-\\x7e]{${minLen},}`, 'g');
  let m;
  let total = 0;
  while ((m = re.exec(ascii)) !== null && total < maxBytes) {
    found.push(m[0]);
    total += m[0].length;
    if (found.length > 4000) break;
  }

  // UTF-16LE runs (Windows paths and PowerShell payloads). Both byte
  // alignments are tried so an odd-length prefix cannot hide a string.
  const re16 = new RegExp(`[\\x20-\\x7e]{${minLen * 2},}`, 'g');
  for (const slice of [buf, buf.subarray(1)]) {
    if (slice.length < 4) continue;
    const utf16 = slice.toString('utf16le');
    re16.lastIndex = 0;
    while ((m = re16.exec(utf16)) !== null && total < maxBytes) {
      found.push(m[0]);
      total += m[0].length;
      if (found.length > 8000) break;
    }
  }

  return found;
}
