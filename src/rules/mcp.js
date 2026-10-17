/**
 * MCP configuration rules.
 *
 * A skill is only half the attack surface: the MCP servers an agent connects
 * to run with the same trust. Skills and plugins routinely ship a
 * `.mcp.json` / `claude_desktop_config.json`, and a hostile entry there is a
 * one-line, silent code-execution primitive.
 */

import { findingAt } from './helpers.js';

const SECRET_KEY_RE =
  /(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)(?:$|_)|^(?:GH|GITHUB|AWS|OPENAI|ANTHROPIC|SLACK|STRIPE|DATABASE|DB)_/i;

const SECRET_VALUE_RE = /^(?:sk-|ghp_|gho_|github_pat_|xox[baprs]-|AKIA|AIza|glpat-)[A-Za-z0-9_\-]{8,}/;

const BYPASS_FLAGS = [
  '--dangerously-skip-permissions',
  '--dangerously-bypass-approvals-and-sandbox',
  '--yolo',
  '--allow-all',
  '--allow-all-tools',
  '--full-auto',
  '--no-sandbox',
  '--trust-all',
  '--disable-sandbox',
];

function serversOf(ctx) {
  const json = ctx.file && ctx.file.json;
  if (!json || typeof json !== 'object') return [];
  const bag = json.mcpServers || json.servers || json.mcp?.servers;
  if (!bag || typeof bag !== 'object') return [];
  return Object.entries(bag).map(([name, spec]) => ({ name, spec: spec && typeof spec === 'object' ? spec : {} }));
}

function at(ctx, token) {
  if (!token) return 0;
  const i = ctx.text.indexOf(token);
  return i === -1 ? 0 : i;
}

function argList(spec) {
  const args = Array.isArray(spec.args) ? spec.args.map(String) : [];
  if (typeof spec.command === 'string') return [spec.command, ...args];
  return args;
}

export const mcpRules = [
  {
    id: 'SG-MCP-001',
    title: 'MCP server pipes remote code into a shell',
    severity: 'critical',
    confidence: 'high',
    category: 'mcp',
    owasp: 'AST06',
    description:
      'An MCP server is configured to fetch a script and execute it in a shell. The code that runs is whatever the remote host serves at launch time.',
    remediation: 'Install the server as a pinned package, or vendor the entry point into the repository.',
    check(ctx) {
      const out = [];
      for (const { name, spec } of serversOf(ctx)) {
        const line = argList(spec).join(' ');
        if (/\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python3?)\b/i.test(line)) {
          out.push(
            findingAt(this, ctx, at(ctx, name), `${name}: ${lineSlug(line)}`, {
              description: `MCP server \`${name}\` runs a downloaded script through a shell.`,
            })
          );
        }
      }
      return out;
    },
  },
  {
    id: 'SG-MCP-002',
    title: 'MCP server runs an unpinned package',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    owasp: 'AST06',
    description:
      'An MCP server is launched with npx/pipx/uvx without a pinned version. The package resolved at launch can change after this configuration was reviewed.',
    remediation: 'Pin the exact version, for example `npx -y @scope/server@1.4.2`.',
    check(ctx) {
      const out = [];
      for (const { name, spec } of serversOf(ctx)) {
        const args = argList(spec);
        const joined = args.join(' ');
        const viaRunner = /\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run)\b/.test(joined);
        if (!viaRunner) continue;
        const pkgs = args.filter(
          (a) => /^[@a-z0-9][\w@/.\-]*$/i.test(a) && !a.startsWith('-') && !['npx', 'bunx', 'uvx'].includes(a)
        );
        const unpinned = pkgs.some((p) => !/(?:^|\/)@?\d+\.\d+/.test(p) && !p.includes('@', 1));
        if (unpinned) {
          out.push(
            findingAt(this, ctx, at(ctx, name), `${name}: ${lineSlug(joined)}`, {
              description: `MCP server \`${name}\` runs an unpinned package: ${lineSlug(joined)}.`,
            })
          );
        }
      }
      return out;
    },
  },
  {
    id: 'SG-MCP-003',
    title: 'Secret hardcoded in MCP server environment',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    owasp: 'AST04',
    description:
      'An MCP server entry embeds what looks like an API key or token in the configuration file, which is committed and shared.',
    remediation: 'Reference the value from the environment or a secret store instead of inlining it.',
    check(ctx) {
      const out = [];
      for (const { name, spec } of serversOf(ctx)) {
        const env = spec.env && typeof spec.env === 'object' ? spec.env : {};
        for (const [key, value] of Object.entries(env)) {
          const val = String(value);
          if (!SECRET_KEY_RE.test(key) && !SECRET_VALUE_RE.test(val)) continue;
          if (val.length < 8 || /^\$\{?[A-Z_]+\}?$/.test(val) || /^<.+>$/.test(val)) continue;
          out.push(
            findingAt(this, ctx, at(ctx, name), `${name}.env.${key}`, {
              redact: true,
              description: `MCP server \`${name}\` hardcodes a credential in env var \`${key}\`.`,
            })
          );
        }
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  {
    id: 'SG-MCP-004',
    title: 'MCP server launched with permission-bypass flags',
    severity: 'critical',
    confidence: 'high',
    category: 'mcp',
    owasp: 'AST05',
    description:
      'A server or harness is started with flags that disable approvals or the sandbox, removing the last human checkpoint before action.',
    remediation: 'Remove the bypass flag. Approvals and sandboxing are the control, not an obstacle.',
    check(ctx) {
      const out = [];
      for (const { name, spec } of serversOf(ctx)) {
        const line = argList(spec).join(' ');
        for (const flag of BYPASS_FLAGS) {
          if (line.includes(flag)) {
            out.push(
              findingAt(this, ctx, at(ctx, name), `${name}: ${flag}`, {
                description: `MCP server \`${name}\` is launched with \`${flag}\`.`,
              })
            );
          }
        }
      }
      return out;
    },
  },
  {
    id: 'SG-MCP-005',
    title: 'Remote MCP server over plaintext HTTP',
    severity: 'medium',
    confidence: 'high',
    category: 'mcp',
    owasp: 'AST06',
    description: 'A remote MCP server is reached over unencrypted HTTP, so its responses can be rewritten in transit.',
    remediation: 'Use HTTPS, and pin the expected host.',
    check(ctx) {
      const out = [];
      for (const { name, spec } of serversOf(ctx)) {
        const url = typeof spec.url === 'string' ? spec.url : '';
        if (/^http:\/\//i.test(url)) {
          out.push(
            findingAt(this, ctx, at(ctx, name), `${name}: ${url}`, {
              description: `MCP server \`${name}\` uses a plaintext HTTP endpoint.`,
            })
          );
        }
      }
      return out;
    },
  },
  {
    id: 'SG-MCP-006',
    title: 'MCP filesystem server rooted at home or root',
    severity: 'high',
    confidence: 'medium',
    category: 'mcp',
    owasp: 'AST03',
    description:
      'A filesystem MCP server is given access to the whole home directory or filesystem, so any instruction the agent reads can reach every file the user owns.',
    remediation: 'Scope the server to the specific project directory it needs.',
    check(ctx) {
      const out = [];
      for (const { name, spec } of serversOf(ctx)) {
        const args = argList(spec);
        const looksFilesystem = /(?:filesystem|file-system|server-filesystem)/i.test(args.join(' '));
        if (!looksFilesystem) continue;
        const broad = args.some((a) => a === '/' || a === '~' || a === '${HOME}' || /^\/(?:Users|home)\/[^/]+$/.test(a));
        if (broad) {
          out.push(
            findingAt(this, ctx, at(ctx, name), `${name}: broad filesystem root`, {
              description: `MCP filesystem server \`${name}\` is rooted at a home or root directory.`,
            })
          );
        }
      }
      return out;
    },
  },
  {
    id: 'SG-MCP-007',
    title: 'MCP auto-approval or blanket trust enabled',
    severity: 'medium',
    confidence: 'medium',
    category: 'mcp',
    owasp: 'AST04',
    description:
      'The configuration pre-approves tool calls or marks servers as trusted, so the agent can act without asking.',
    remediation: 'Require approval for tool calls, especially from servers that touch the network or the filesystem.',
    check(ctx) {
      const out = [];
      const json = ctx.file && ctx.file.json;
      if (!json || typeof json !== 'object') return out;
      const autoKeys = ['autoApprove', 'auto_approve', 'alwaysAllow', 'always_allow', 'trust', 'trusted', 'dangerouslySkipPermissions'];
      for (const key of autoKeys) {
        if (json[key] === true || (Array.isArray(json[key]) && json[key].length > 0)) {
          out.push(
            findingAt(this, ctx, at(ctx, key), `${key}: ${JSON.stringify(json[key])}`, {
              description: `MCP configuration sets \`${key}\`, which pre-approves tool calls.`,
            })
          );
        }
      }
      return out;
    },
  },
];

function lineSlug(value, n = 90) {
  const one = String(value).replace(/\s+/g, ' ').trim();
  return one.length > n ? `${one.slice(0, n - 1)}…` : one;
}
