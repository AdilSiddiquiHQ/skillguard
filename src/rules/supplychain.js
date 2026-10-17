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
      // Fetching a *document* (a spec, a README) is normal; fetching a script
      // or piping remote content into an interpreter is not.
      /\b(?:curl|wget|iwr|Invoke-WebRequest|fetch|requests\.get)\b[^\n]{0,160}(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com|codeload\.github\.com)[^\n]{0,120}\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|ps1|bat|cmd|exe|bin)\b/gi,
      /\b(?:curl|wget)\b[^\n]{0,160}(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)[^\n]{0,120}\|\s*(?:sh|bash|zsh|python3?|node|perl|ruby)\b/gi,
      /\b(?:curl|wget)\b[^\n]{0,160}(?:pastebin\.com|paste\.ee|ghostbin|termbin\.com|0x0\.st|hastebin)[^\n]{0,120}(?:\|\s*(?:sh|bash|python3?|node)|-o\s+\S+\.(?:sh|py|js|bin|exe))/gi,
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
  {
    id: 'SG-SC-006',
    title: 'Rewrites package-manager registry configuration',
    severity: 'high',
    confidence: 'high',
    category: 'supply-chain',
    owasp: 'AST06',
    description:
      'Writes a registry or index setting into a package-manager config file (.npmrc, .yarnrc, pip.conf, .gemrc, settings.xml). This is the exact technique used in a documented scanner bypass: every future install silently routes through an attacker-controlled mirror.',
    remediation:
      'Never modify registry configuration from a skill. Use the default registry, or have the user opt in explicitly.',
    patterns: [
      /(?:>|>>|tee\s+-?a?|cat\s*>)\s*[^\n]{0,80}?\.(?:npmrc|yarnrc|npmrc\.js|gemrc|netrc|pypirc|condarc)\b/gi,
      /\b(?:pip|python3?)\s+-m\s+pip\b[^\n]{0,60}config\s+set\s+[^\n]*(?:index-url|extra-index-url)/gi,
      /\bnpm\s+config\s+set\s+[^\n]{0,80}(?:registry|@[a-z0-9-]+:registry)/gi,
      /\byarn\s+config\s+set\s+[^\n]{0,80}registry/gi,
      /\b(?:gem\s+sources|go\s+env\s+-w\s+GOPROXY|cargo\s+config\s+set\b)[^\n]{0,80}/gi,
      /\bpip\.conf\b[^\n]{0,80}\bindex-url\b/gi,
    ],
  },
  {
    id: 'SG-SC-007',
    title: 'Injects a dynamic library into other processes',
    severity: 'critical',
    confidence: 'high',
    category: 'supply-chain',
    owasp: 'AST05',
    description:
      'Uses LD_PRELOAD, DYLD_INSERT_LIBRARIES or a similar mechanism to inject a library into another process. It hijacks code you did not write and cannot see.',
    remediation: 'Remove. There is no reason for a skill to inject libraries into other processes.',
    patterns: [
      /\bLD_PRELOAD\b\s*=/gi,
      /\bDYLD_INSERT_LIBRARIES\b\s*=/gi,
      /\bLD_LIBRARY_PATH\b\s*=[^\n]{0,80}/gi,
      /\bDYLD_FORCE_FLAT_NAMESPACE\b/gi,
    ],
  },
  {
    id: 'SG-SC-008',
    title: 'Compiles and loads code at runtime',
    severity: 'high',
    confidence: 'medium',
    category: 'supply-chain',
    owasp: 'AST05',
    description:
      'Invokes a compiler or linker to build a library from embedded source, then loads it. This is a documented technique for shipping a payload as a harmless-looking string and a way to evade review entirely.',
    remediation: 'Ship source the agent interprets, never a build step that produces a binary at runtime.',
    patterns: [
      // Require a real compile invocation: a C-family source file, or an
      // output artifact. A quoted list of flags in a Python array is not one.
      /\b(?:gcc|clang|cc|g\+\+|zig\s+cc)\b[^\n]{0,160}[^\s"'`]\.(?:c|cc|cpp|cxx)\b/gi,
      /\b(?:gcc|clang|cc|g\+\+|zig\s+cc)\b[^\n]{0,160}-o\s*['"]?[^\s"',]+\.(?:so|dylib|dll|o)\b/gi,
      /\b(?:cargo|rustc|go\s+build)\b[^\n]{0,80}--(?:release|target)/gi,
      /\b(?:cc|gcc|clang)\b[^\n]{0,60}<<['"]?\w*['"]?[\s\S]{0,200}/g,
    ],
  },
  {
    id: 'SG-SC-009',
    title: 'Disables TLS or certificate verification',
    severity: 'high',
    confidence: 'high',
    category: 'supply-chain',
    owasp: 'AST06',
    description:
      'Turns off TLS verification (NODE_TLS_REJECT_UNAUTHORIZED, strict-ssl=false, --insecure, GIT_SSL_NO_VERIFY). This enables man-in-the-middle tampering with everything the agent downloads.',
    remediation: 'Keep certificate verification on. Fix the underlying trust problem instead of disabling the check.',
    patterns: [
      /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/gi,
      /\bGIT_SSL_NO_VERIFY\s*=\s*(?:1|true)/gi,
      /\bstrict-ssl\s*[=:]\s*(?:false|0)/gi,
      /\b(?:curl|wget)\b[^\n]{0,120}(?:--insecure\b|-k\b|--no-check-certificate)/gi,
      /\bpip3?\s+install\b[^\n]{0,80}--trusted-host\b/gi,
      /\bnpm\s+(?:i|install|ci)\b[^\n]{0,80}--strict-ssl[= ]?false/gi,
    ],
  },
  {
    id: 'SG-SC-010',
    title: 'Installs software outside the project directory',
    severity: 'medium',
    confidence: 'medium',
    category: 'supply-chain',
    owasp: 'AST06',
    description:
      'Installs packages system-wide or globally, changing the environment for every project on the machine and expanding the blast radius of the skill.',
    remediation: 'Install into a project-local, disposable environment (a virtualenv or node_modules).',
    patterns: [
      /\b(?:npm|pnpm|yarn)\s+(?:i|install|add|global\s+add)\s+[^\n]*-g\b/gi,
      /\bnpm\s+(?:i|install)\s+-g\b/gi,
      /\bpip3?\s+install\s+[^\n]*--user\b/gi,
      /\bapt(?:-get)?\s+(?:install|remove)\b/gi,
      /\bbrew\s+(?:install|uninstall)\b/gi,
      /\bsnap\s+install\b/gi,
    ],
  },
];
