/**
 * Credential and secret-access rules (OWASP Agentic Skills: AST03).
 * A skill that reads keys, tokens or keychains is either badly scoped or
 * preparing to exfiltrate them.
 *
 * Precision note: mentioning a credential path in documentation is not the
 * same as accessing it. These rules only fire on a file path that sits next to
 * an *access* action, so reference material ("the .env file holds secrets")
 * stays quiet while `cat ~/.ssh/id_rsa` does not.
 */

import { eachMatch, findingAt, inDefensiveContext, lineAt } from './helpers.js';

/** Paths that hold credentials, private keys or session tokens. */
const SENSITIVE_PATH =
  /(?:~?\/?\.ssh\/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bknown_hosts\b|\bauthorized_keys\b|\.aws\/credentials|\bAWS_SHARED_CREDENTIALS_FILE\b|\bAWS_CONFIG_FILE\b|(?:^|[\s'"`/=(])\.env(?:\.(?:local|production|prod|development|dev|staging|test|secrets?))?(?![.\w])|\.npmrc\b|\.netrc\b|\.git-credentials\b|\.pypirc\b|\.gem\/credentials\b|\.docker\/config\.json|\blogin\.keychain\b|\bsecurity\s+find-generic-password\b|\bcredentials\.json\b|\btoken\.json\b|\.config\/gh\/hosts\.yml|\.config\/gcloud\/|\bkubeconfig\b|\/proc\/(?:self|\d+)\/environ)/gi;

/**
 * The path must sit directly after an access verb or call. Requiring adjacency,
 * rather than "a verb somewhere on the line", is what separates an instruction
 * like `cat ~/.ssh/id_rsa` from prose like "writes them where they belong
 * (`.env`)".
 */
const ACCESS_BEFORE =
  /(?:\b(?:cat|less|more|head|tail|grep|egrep|awk|sed|strings|cp|mv|scp|rsync|tar|zip|unzip|base64|xxd|openssl|curl|wget|nc|ncat|open|read|type|source|import|require|dump|print|echo|del|copy|move|Get-Content)\s*['"`(]*\s*|\b(?:readfile(?:sync)?|createreadstream|read_text|read_bytes|open)\s*\(\s*['"`]?)$/i;

/** Paths that are an access on their own, regardless of a nearby verb. */
const SELF_ACCESS = /security\s+find-generic-password|\/proc\/(?:self|\d+)\/environ/i;

export const credentialRules = [
  {
    id: 'SG-CRED-001',
    title: 'Access to sensitive credential files',
    severity: 'critical',
    confidence: 'high',
    category: 'credentials',
    owasp: 'AST03',
    description:
      'Reads, copies or transmits files that hold credentials, private keys or session tokens (SSH, AWS, .env, npm, Docker, browser cookies, keychains).',
    remediation:
      'Never read credential stores. If a secret is required, ask the user to provide it explicitly via an environment variable you document.',
    check(ctx) {
      const out = [];
      for (const { index, match } of eachMatch(SENSITIVE_PATH, ctx.text)) {
        if (!SELF_ACCESS.test(match[0])) {
          const line = lineAt(ctx.text, index);
          const offset = index - ctx.text.lastIndexOf('\n', index - 1) - 1;
          const before = line.slice(0, offset);
          if (!ACCESS_BEFORE.test(before)) continue;
          if (inDefensiveContext(ctx.text, index, 400, match[0].length)) continue;
        }
        out.push(findingAt(this, ctx, index, match[0].trim()));
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  {
    id: 'SG-CRED-002',
    title: 'Prints or forwards a secret environment variable',
    severity: 'high',
    confidence: 'high',
    category: 'credentials',
    owasp: 'AST03',
    description:
      'Prints, dumps or pipes an environment variable that holds a secret (token, API key, password). Naming such a variable is normal; echoing or forwarding its value is not.',
    remediation:
      'Never print or transmit secret variables. Read only the specific, non-secret values you need, and keep secret handling inside the API client.',
    check(ctx) {
      const SECRET_NAME =
        '(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIALS?|ACCESS[_-]?KEY)';
      const NAMED =
        'AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|NPM_TOKEN|PYPI_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|STRIPE_SECRET_KEY|STRIPE_API_KEY|SLACK_TOKEN|SLACK_BOT_TOKEN|DISCORD_TOKEN|DATABASE_URL|PRIVATE_KEY|SECRET_KEY|MASTER_KEY';
      const dumped = new RegExp(
        `\\b(?:echo|printf|print|printenv|env|cat|base64|xxd|export|set)\\b[^\\n]{0,40}\\$\\{?(?:[A-Za-z_]*${SECRET_NAME}[A-Za-z_]*|${NAMED})\\}?(?!\\s*[=:])`,
        'gi'
      );
      const piped = new RegExp(
        `\\$\\{?(?:[A-Za-z_]*${SECRET_NAME}[A-Za-z_]*|${NAMED})\\}?\\b[^\\n]{0,30}\\|\\s*(?:curl|wget|nc|ncat|base64|openssl|dig|nslookup|mail|sendmail)`,
        'gi'
      );
      const out = [];
      const seen = new Set();
      for (const re of [dumped, piped]) {
        for (const { index, match } of eachMatch(re, ctx.text)) {
          if (seen.has(index)) continue;
          seen.add(index);
          out.push(findingAt(this, ctx, index, match[0].trim()));
          if (out.length >= 5) break;
        }
      }
      return out;
    },
  },
  {
    id: 'SG-CRED-003',
    title: 'Broad environment dump',
    severity: 'medium',
    confidence: 'medium',
    category: 'credentials',
    owasp: 'AST03',
    description:
      'Dumps, prints or forwards the entire environment, which commonly leaks secrets into agent transcripts and logs.',
    remediation: 'Read individual variables that are documented and non-sensitive.',
    patterns: [
      // Require whitespace before the redirect: `env | curl` is a dump, but a
      // regex alternation such as `env|getenv\(` is not.
      /\b(?:env|printenv)\s+(?:>|>>|\|)\s*\S+/gi,
      /\b(?:print|printf|json\.dumps?|str|repr|dict|list|logging\.[a-z]+|logger\.[a-z]+)\s*\(\s*os\.environ\b/gi,
      /\bos\.environ\b[^\n]{0,60}(?:\+|\||>>?)\s*\S*(?:curl|wget|nc|ncat|requests|urllib|socket|http)/gi,
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
