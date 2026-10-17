/**
 * Compiled-artefact and container rules.
 *
 * The `.pyc` poisoning bypass worked because the scanner never looked at the
 * bytecode, and the `.docx` bypass worked because the scanner never opened the
 * archive. These rules close both gaps and add the classic supply-chain tell:
 * a binary that disagrees with the source sitting next to it.
 */

import { extensionOf } from '../archive.js';
import { findingAt, truncate } from './helpers.js';

const ACTIVE_ENTRY_EXT = new Set([
  '.sh', '.bash', '.zsh', '.fish', '.ksh', '.ps1', '.psm1', '.bat', '.cmd',
  '.exe', '.dll', '.so', '.dylib', '.py', '.pyc', '.pyo', '.js', '.mjs', '.cjs',
  '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.scr', '.com', '.jar', '.app',
  '.command', '.hta', '.msi', '.deb', '.rpm', '.apk',
]);

const DANGEROUS_STRINGS = [
  [/\bLD_PRELOAD\b|\bDYLD_INSERT_LIBRARIES\b/i, 'dynamic-library injection'],
  [/\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:sh|bash|zsh)\b/i, 'remote shell pipeline'],
  [/\bchmod\s+\+?x\b/i, 'makes a dropped file executable'],
  [/\b(?:nc|ncat|netcat)\s+-[a-z]*e\b/i, 'reverse shell'],
  [/\bcmd\.exe\s+\/c\b|powershell(?:\.exe)?\s+-(?:enc|e|Command)\b/i, 'Windows command execution'],
  [/\b(?:ProcessStartInfo|CreateProcess|WScript\.Shell|ShellExecute)\b/i, 'process spawning API'],
  [/\/(?:etc\/(?:passwd|shadow)|\.ssh\/(?:id_rsa|id_ed25519|authorized_keys))\b/i, 'credential file access'],
  [/\bAWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID)\b|\bANTHROPIC_API_KEY\b|\bOPENAI_API_KEY\b/i, 'cloud credential names'],
  [/\bbase64\s+-d\b|\bfrombase64string\b|\batob\s*\(/i, 'inline base64 decoding'],
  [/\b(?:0x)?[0-9a-f]{2}(?:\s*(?:0x)?[0-9a-f]{2}){14,}\b/i, 'shellcode-like byte sequence'],
];

const OPAQUE_EXT = new Set([
  '.bin', '.dat', '.pak', '.db', '.sqlite', '.so', '.dylib', '.dll', '.pyc',
  '.pyo', '.class', '.o', '.a', '.ko', '.wasm', '.exe', '.msi', '.dmg', '.iso',
  '.img', '.vmdk', '.woff', '.woff2', '.ttf', '.otf', '.pdf', '.psd',
]);

const KNOWN_IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.bmp', '.avif']);

function fileName(path) {
  return String(path).split('/').pop().toLowerCase();
}

export const artifactRules = [
  {
    id: 'SG-ART-001',
    title: 'Compiled artefact with no matching source',
    severity: 'critical',
    confidence: 'high',
    category: 'artifacts',
    owasp: 'AST06',
    perSkill: true,
    description:
      'The skill ships compiled bytecode or a shared library (for example a .pyc) without the source file it was built from. This is the exact shape of the poisoned-bytecode supply-chain attack: the bytecode contains behaviour the visible source does not.',
    remediation:
      'Delete compiled artefacts. Ship readable source only, and let the agent interpret it.',
    check(ctx) {
      const out = [];
      const files = ctx.files || [];
      const sources = new Set(
        files.map((f) => fileName(f.path).replace(/\.(py|js|mjs|cjs|ts|rb|pl|php)$/, ''))
      );
      for (const file of files) {
        const ext = extensionOf(file.path);
        if (!['.pyc', '.pyo', '.class', '.o', '.so', '.dylib', '.dll', '.node', '.wasm'].includes(ext)) {
          continue;
        }
        const stem = fileName(file.path).replace(/\.(pyc|pyo|class|o|so|dylib|dll|node|wasm)$/, '');
        const base = stem.replace(/\.cpython-\d+$/, '');
        if (ext === '.pyc' || ext === '.pyo') {
          const hasSource = sources.has(base) || files.some((f) => fileName(f.path) === `${base}.py`);
          if (hasSource) continue;
        }
        out.push(
          findingAt(this, ctx, 0, `${file.path} (${ext})`, {
            description: `Compiled artefact \`${file.path}\` has no matching reviewable source. Bytecode can differ from the source it claims to be built from.`,
          })
        );
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  {
    id: 'SG-ART-002',
    title: 'Suspicious strings inside a binary artefact',
    severity: 'high',
    confidence: 'medium',
    category: 'artifacts',
    owasp: 'AST06',
    description:
      'A bundled binary contains strings strongly associated with payloads and post-exploitation: library injection, reverse shells, credential paths or inline base64 decoding.',
    remediation:
      'Remove the binary, or document and vendor it from a pinned, signed upstream release. Never trust a binary you cannot read.',
    check(ctx) {
      const strings = (ctx.file && ctx.file.strings) || [];
      if (strings.length === 0) return [];
      const out = [];
      const seen = new Set();
      for (const value of strings) {
        for (const [re, label] of DANGEROUS_STRINGS) {
          if (seen.has(label)) continue;
          if (re.test(value)) {
            seen.add(label);
            out.push(
              findingAt(this, ctx, 0, `${label}: ${truncate(value, 60)}`, {
                description: `Binary contains a string matching "${label}".`,
              })
            );
            break;
          }
        }
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  {
    id: 'SG-ART-003',
    title: 'Executable or script payload inside an archive',
    severity: 'high',
    confidence: 'high',
    category: 'artifacts',
    owasp: 'AST06',
    views: ['archive'],
    description:
      'An archive or document (such as .docx, .zip, .jar) contains an executable or script entry. This is how a payload rides along inside a file a reviewer would open as text.',
    remediation:
      'Rebuild the document without embedded scripts, or ship the payload as explicit, reviewable source.',
    check(ctx) {
      const name = ctx.entryName;
      if (!name) return [];
      const ext = extensionOf(name);
      const isMacro = /vbaProject\.bin$/i.test(name) || /\.(docm|xlsm|pptm|dotm|xltm)$/i.test(name);
      if (!ACTIVE_ENTRY_EXT.has(ext) && !isMacro) return [];
      return [
        findingAt(this, ctx, 0, name, {
          file: ctx.fileLabel,
          description: `Archive entry \`${name}\` is an executable, script or macro payload embedded in a document.`,
        }),
      ];
    },
  },
  {
    id: 'SG-ART-004',
    title: 'Opaque file type that cannot be reviewed',
    severity: 'medium',
    confidence: 'medium',
    category: 'artifacts',
    owasp: 'AST06',
    perSkill: true,
    description:
      'The skill ships one or more files that a human cannot read and a code scanner cannot fully analyse. Opaque blobs defeat review and are outside the Agent Skills specification.',
    remediation:
      'Keep skills to reviewable text. If a binary asset is unavoidable, pin it to a checksum and explain why.',
    check(ctx) {
      const out = [];
      for (const file of ctx.files || []) {
        const ext = extensionOf(file.path);
        if (KNOWN_IMAGE_EXT.has(ext)) continue;
        if (!OPAQUE_EXT.has(ext)) continue;
        out.push(
          findingAt(this, ctx, 0, `${file.path} (${ext})`, {
            description: `\`${file.path}\` is an opaque file type (${ext}) that cannot be fully reviewed or statically analysed.`,
          })
        );
        if (out.length >= 5) break;
      }
      return out;
    },
  },
];
