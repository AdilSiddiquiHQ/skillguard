/**
 * Bundled-asset rules (OWASP Agentic Skills: AST10).
 * Skills frequently ship helper scripts. Those files run with the user's
 * privileges, so executable payloads deserve scrutiny.
 */

import { findingAt } from './helpers.js';

const EXECUTABLE_MAGIC = [
  { sig: '7f454c46', name: 'ELF executable' },
  { sig: 'feedface', name: 'Mach-O executable' },
  { sig: 'feedfacf', name: 'Mach-O executable (64-bit)' },
  { sig: 'cffaedfe', name: 'Mach-O executable (little-endian)' },
  { sig: 'cafebabe', name: 'Mach-O fat binary or Java class' },
  { sig: '4d5a', name: 'Windows PE executable' },
];

const ARCHIVE_MAGIC = [
  { sig: '504b0304', name: 'zip archive' },
  { sig: '1f8b', name: 'gzip archive' },
  { sig: '425a68', name: 'bzip2 archive' },
  { sig: 'fd377a585a00', name: 'xz archive' },
];

const HIGH_RISK_EXT = /\.(?:exe|dll|so|dylib|scr|msi|com|jar|class|vbs|vbe|wsf|hta|ps1|bat|cmd|lnk|desktop|apk|dmg|pkg|deb|rpm|app)$/i;

export const assetRules = [
  {
    id: 'SG-ASSET-001',
    title: 'Executable binary bundled in the skill',
    severity: 'high',
    confidence: 'high',
    category: 'assets',
    owasp: 'AST10',
    description:
      'Ships a compiled executable. Its behaviour cannot be reviewed as source, and it runs with the user\'s privileges.',
    remediation: 'Ship source instead. If a binary is unavoidable, document the build and publish checksums.',
    check(ctx) {
      const file = ctx.file;
      if (!file || !file.binary || !file.magic) return [];
      const match = EXECUTABLE_MAGIC.find((m) => file.magic.startsWith(m.sig));
      if (!match) return [];
      return [findingAt(this, ctx, 0, `${file.path} (${match.name})`)];
    },
  },
  {
    id: 'SG-ASSET-002',
    title: 'High-risk script or package file type',
    severity: 'medium',
    confidence: 'medium',
    category: 'assets',
    owasp: 'AST10',
    description:
      'Bundles a script or package type that executes automatically or is commonly used to deliver payloads.',
    remediation: 'Explain why the file is needed and make it reviewable. Prefer plain, documented scripts.',
    check(ctx) {
      const file = ctx.file;
      if (!file) return [];
      const m = HIGH_RISK_EXT.exec(file.path);
      if (!m) return [];
      return [findingAt(this, ctx, 0, file.path)];
    },
  },
  {
    id: 'SG-ASSET-003',
    title: 'Archive bundled in the skill',
    severity: 'info',
    confidence: 'medium',
    category: 'assets',
    owasp: 'AST10',
    description: 'Contains a compressed archive whose contents are not visible during review.',
    remediation: 'Expand and commit the contents, or document the archive and its checksum.',
    check(ctx) {
      const file = ctx.file;
      if (!file || !file.binary || !file.magic) return [];
      const match = ARCHIVE_MAGIC.find((m) => file.magic.startsWith(m.sig));
      if (!match) return [];
      return [findingAt(this, ctx, 0, `${file.path} (${match.name})`)];
    },
  },
];
