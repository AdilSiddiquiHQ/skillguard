/**
 * Supply-chain rules (OWASP Agentic Skills: AST06).
 * Skills that install or fetch code at runtime expand the trust boundary
 * far beyond the repository you reviewed.
 */

export const supplyChainRules = [
  {
    id: 'SG-SC-001',
    title: 'Installs dependencies from a URL or VCS',
    severity: 'high',
    confidence: 'high',
    category: 'supply-chain',
    owasp: 'AST06',
    description: 'Installs packages from a URL, git remote or alternate registry instead of the pinned registry.',
    remediation: 'Pin dependencies to a version from the default registry and commit a lockfile.',
    patterns: [
      /\b(?:npm\s+(?:i|install|add)|pnpm\s+(?:add|install)|yarn\s+add)\s+[^\n]*(?:https?:\/\/|git\+|github:|gitlab:|bitbucket:)/gi,
      /\bpip3?\s+install\s+[^\n]*(?:git\+|https?:\/\/|--index-url|--extra-index-url|-f\s)/gi,
      /\b(?:gem\s+install|go\s+install)\s+[^\n]*(?:https?:\/\/|git\+)/gi,
      /\bcargo\s+install\s+[^\n]*--git\b/gi,
    ],
  },
  {
    id: 'SG-SC-002',
    title: 'Downloads and unpacks remote code',
    severity: 'critical',
    confidence: 'high',
    category: 'supply-chain',
    owasp: 'AST06',
    description: 'Fetches an archive or binary and unpacks or installs it — the classic delivery step for a malicious payload.',
    remediation: 'Vendor the artifact, pin a checksum, and verify the signature.',
    patterns: [
      /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:tar|unzip|gunzip|zstd|bunzip2)\b/gi,
      /\b(?:curl|wget)\b[^\n]{0,200}-O[^\n]{0,120}\b(?:install|setup|bootstrap|payload|update)\.(?:sh|bin|exe|dmg|pkg|deb|rpm)\b/gi,
      /\bInvoke-WebRequest\b[^\n]{0,160}-OutFile[^\n]{0,80}\.(?:exe|zip|dll|ps1)/gi,
    ],
  },
  {
    id: 'SG-SC-003',
    title: 'Fetches code from a paste or raw-content host at runtime',
    severity: 'high',
    confidence: 'medium',
    category: 'supply-chain',
    owasp: 'AST06',
    description: 'Pulls scripts from raw repositories, gists or paste services while running. Content can change after review.',
    remediation: 'Inline or vendor the code so what the user reviewed is what runs.',
    patterns: [
      /\b(?:curl|wget|iwr|Invoke-WebRequest|fetch|requests\.get)\b[^\n]{0,160}(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com|codeload\.github\.com)/gi,
      /\b(?:curl|wget)\b[^\n]{0,160}(?:pastebin\.com|paste\.ee|ghostbin|termbin\.com|0x0\.st|hastebin)/gi,
    ],
  },
  {
    id: 'SG-SC-004',
    title: 'Runs unpinned packages on the fly',
    severity: 'medium',
    confidence: 'medium',
    category: 'supply-chain',
    owasp: 'AST06',
    description: 'Executes a package without pinning a version (npx -y, uvx, pipx run). The resolved code can change between runs.',
    remediation: 'Pin the exact version, for example npx package@1.2.3.',
    patterns: [
      /\bnpx\s+(?:-y|--yes)\b/gi,
      /\buvx\s+[a-z0-9@]/gi,
      /\bpipx\s+run\s+[a-z0-9]/gi,
      /\bbunx\s+[a-z0-9]/gi,
    ],
  },
  {
    id: 'SG-SC-005',
    title: 'Points the package manager at a non-default registry',
    severity: 'high',
    confidence: 'medium',
    category: 'supply-chain',
    owasp: 'AST06',
    description: 'Overrides the registry or index URL, which redirects installs to an attacker-controlled source.',
    remediation: 'Use the default registry. If a mirror is truly required, document it and pin it.',
    patterns: [
      /\b(?:npm|pnpm|yarn)\b[^\n]{0,80}--registry\s+https?:\/\//gi,
      /\bregistry\s*=\s*https?:\/\//gi,
      /\bpip3?\s+[^\n]{0,60}(?:--index-url|--extra-index-url)\s+https?:\/\//gi,
    ],
  },
];
