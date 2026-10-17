/**
 * Credential and secret-access rules (OWASP Agentic Skills: AST03).
 * A skill that reads keys, tokens or keychains is either badly scoped or
 * preparing to exfiltrate them.
 */

export const credentialRules = [
  {
    id: 'SG-CRED-001',
    title: 'Access to sensitive credential files',
    severity: 'critical',
    confidence: 'high',
    category: 'credentials',
    owasp: 'AST03',
    description:
      'References files that hold credentials, private keys or session tokens (SSH, AWS, .env, npm, Docker, browser cookies, keychains).',
    remediation:
      'Never read credential stores. If a secret is required, ask the user to provide it explicitly via an environment variable you document.',
    patterns: [
      /~?\/?\.ssh\/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bknown_hosts\b|\bauthorized_keys\b/gi,
      /\.aws\/credentials|\bAWS_SHARED_CREDENTIALS_FILE\b|\bAWS_CONFIG_FILE\b/gi,
      /(?:^|[\s'"`/])\.env(?:\.[a-z0-9]+)?\b/gi,
      /\.npmrc\b|\.netrc\b|\.git-credentials\b|\.pypirc\b|\.gem\/credentials\b/gi,
      /\.docker\/config\.json|\bconfig\.json\b[^\n]{0,20}auths/gi,
      /\blogin\.keychain\b|\bKeychains?\b|\bsecurity\s+find-generic-password\b/gi,
      /\bCookies?\b[^\n]{0,30}(?:Chrome|Firefox|Safari|Brave|Edge)|(?:Chrome|Firefox|Safari)[^\n]{0,40}\bCookies?\b/gi,
      /\bcredentials\.json\b|\bservice[-_]account\b|\btoken\.json\b/gi,
      /\.config\/gh\/hosts\.yml|\.config\/gcloud\/|\bkubeconfig\b/gi,
      /\/proc\/self\/environ|\/proc\/\d+\/environ/gi,
    ],
  },
  {
    id: 'SG-CRED-002',
    title: 'Reads secret environment variables',
    severity: 'high',
    confidence: 'high',
    category: 'credentials',
    owasp: 'AST03',
    description:
      'Reads or prints environment variables that typically contain secrets (tokens, API keys, passwords).',
    remediation:
      'Reference only the specific, non-secret variables you need. Never enumerate the environment or match variables by wildcard.',
    patterns: [
      /\b(?:echo|printf|print|printenv|env|cat|export)\b[^\n]{0,40}\$\{?[A-Za-z_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY)[A-Za-z_]*\}?/gi,
      /\$\{?(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY|SLACK_(?:TOKEN|BOT_TOKEN)|DATABASE_URL|PRIVATE_KEY|SECRET_KEY)\b/gi,
      /\bprocess\.env\b(?!\s*\.\s*[A-Z_]*$)/g,
      /\bprintenv\s*$/gm,
    ],
  },
  {
    id: 'SG-CRED-003',
    title: 'Broad environment dump',
    severity: 'medium',
    confidence: 'medium',
    category: 'credentials',
    owasp: 'AST03',
    description: 'Dumps the entire environment, which commonly leaks secrets into agent transcripts and logs.',
    remediation: 'Read individual variables that are documented and non-sensitive.',
    patterns: [
      /\b(?:env|printenv)\s*(?:>|>>|\|)\s*\S+/gi,
      /os\.environ\b(?!\s*\[)/g,
      /\bGet-ChildItem\s+env:\\/gi,
    ],
  },
  {
    id: 'SG-CRED-004',
    title: 'Access to the SSH agent or git credential helper',
    severity: 'high',
    confidence: 'medium',
    category: 'credentials',
    owasp: 'AST03',
    description: 'Uses the SSH agent socket or git credential helpers to obtain credentials the user did not hand over.',
    remediation: 'Use a scoped, read-only deploy key that the user explicitly provides.',
    patterns: [
      /\bSSH_AUTH_SOCK\b/gi,
      /ssh-add\s+-l|ssh-add\s+--list/gi,
      /git\s+credential\s+(?:fill|approve|get)/gi,
      /\bgh\s+auth\s+token\b/gi,
    ],
  },
];
