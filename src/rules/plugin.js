/**
 * Plugin manifest rules.
 *
 * Claude Code (and compatible harnesses) bundle skills together with hooks,
 * commands, agents and MCP servers in a `plugin.json`. Hooks run shell
 * commands automatically on lifecycle events, which makes the manifest itself
 * executable content that deserves the same scrutiny as a SKILL.md body.
 */

import { findingAt, truncate } from './helpers.js';

const HOOK_EVENTS = [
  'PreToolUse', 'PostToolUse', 'UserPromptSubmit', 'Notification', 'Stop',
  'SubagentStop', 'PreCompact', 'SessionStart', 'SessionEnd',
];

function isPluginManifest(ctx) {
  const json = ctx.file && ctx.file.json;
  if (!json || typeof json !== 'object') return false;
  if (json.hooks && typeof json.hooks === 'object') return true;
  return /(^|\/)plugin\.json$/i.test(ctx.file.path || '');
}

/** Flatten hooks into `{ event, matcher, command }` records. */
function hookEntries(json) {
  const out = [];
  const hooks = json.hooks;
  if (!hooks || typeof hooks !== 'object') return out;
  for (const [event, value] of Object.entries(hooks)) {
    const groups = Array.isArray(value) ? value : [value];
    for (const group of groups) {
      if (!group || typeof group !== 'object') continue;
      const matcher = group.matcher ?? null;
      const inner = Array.isArray(group.hooks) ? group.hooks : [group];
      for (const h of inner) {
        if (h && typeof h.command === 'string') {
          out.push({ event, matcher, command: h.command });
        }
      }
    }
  }
  return out;
}

function position(ctx, token) {
  if (!token) return 0;
  const i = ctx.text.indexOf(token);
  return i === -1 ? 0 : i;
}

export const pluginRules = [
  {
    id: 'SG-PLUG-001',
    title: 'Plugin hook executes a shell command',
    severity: 'high',
    confidence: 'high',
    category: 'plugin',
    owasp: 'AST05',
    description:
      'The plugin registers a lifecycle hook that runs a shell command. Hooks execute automatically, so installing the plugin runs this code without a per-action prompt.',
    remediation:
      'Remove hooks you cannot fully read, or make them a no-op. Prefer explicit user-invoked commands over automatic hooks.',
    check(ctx) {
      if (!isPluginManifest(ctx)) return [];
      const out = [];
      for (const hook of hookEntries(ctx.file.json)) {
        out.push(
          findingAt(this, ctx, position(ctx, hook.command), `${hook.event}: ${truncate(hook.command, 80)}`, {
            description: `Hook \`${hook.event}\` runs a shell command: ${truncate(hook.command, 100)}`,
          })
        );
        if (out.length >= 5) break;
      }
      return out;
    },
  },
  {
    id: 'SG-PLUG-002',
    title: 'Plugin hook downloads and runs remote code',
    severity: 'critical',
    confidence: 'high',
    category: 'plugin',
    owasp: 'AST06',
    description:
      'A lifecycle hook fetches a script from the network and executes it. The hook runs automatically, so this is unattended remote code execution.',
    remediation: 'Vendor the script, pin it to a checksum, and run it only on explicit user action.',
    check(ctx) {
      if (!isPluginManifest(ctx)) return [];
      const out = [];
      for (const hook of hookEntries(ctx.file.json)) {
        if (
          /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python3?)\b/i.test(hook.command) ||
          /\b(?:Invoke-Expression|iex)\b[^\n]{0,120}(?:DownloadString|iwr|Invoke-WebRequest)/i.test(hook.command)
        ) {
          out.push(
            findingAt(this, ctx, position(ctx, hook.command), `${hook.event}: ${truncate(hook.command, 80)}`, {
              description: `Hook \`${hook.event}\` downloads and executes remote code.`,
            })
          );
        }
      }
      return out;
    },
  },
  {
    id: 'SG-PLUG-003',
    title: 'Plugin hook runs on every event without a matcher',
    severity: 'medium',
    confidence: 'medium',
    category: 'plugin',
    owasp: 'AST04',
    description:
      'A tool hook has no matcher, so it runs on every tool call the agent makes rather than a narrow, named tool. This maximises the blast radius of the hook.',
    remediation: 'Add a matcher that limits the hook to the specific tools it needs.',
    check(ctx) {
      if (!isPluginManifest(ctx)) return [];
      const out = [];
      for (const hook of hookEntries(ctx.file.json)) {
        if ((hook.event === 'PreToolUse' || hook.event === 'PostToolUse') && !hook.matcher) {
          out.push(
            findingAt(this, ctx, position(ctx, hook.command), `${hook.event}: no matcher`, {
              description: `Hook \`${hook.event}\` has no matcher and therefore runs on every tool call.`,
            })
          );
        }
      }
      return out;
    },
  },
];

export { HOOK_EVENTS };
