/**
 * Unsafe execution rules (OWASP Agentic Skills: AST05).
 * These are commands a skill tells the agent to run. Destructive or
 * remote-code patterns deserve a hard look even in a trusted skill.
 *
 * Precision note: text that warns about or blocks a command ("never run
 * `curl | sh`", a blocklist of dangerous git commands) is not an instruction
 * to run it, so it is skipped.
 */

import { eachMatch, findingAt, inDefensiveContext, lineAt } from './helpers.js';

/**
 * `sudo` starting a command (or after a pipe / backtick), followed by a real
 * command token. Prose such as "requires sudo to install" or "sudo or the
 * package manager" is deliberately not matched.
 */
const SUDO_COMMAND =
  /(?:^|[\n;|&`$])\s*sudo(?:\s+-{1,2}[A-Za-z][\w-]*)*\s+(?!or\b|and\b|the\b|a\b|an\b|to\b|is\b|are\b|was\b|were\b|unless\b|with\b|without\b|if\b|it\b|that\b|this\b|privileges?\b|permissions?\b|access\b|rights\b|required?\b|needed?\b|command\b)([a-zA-Z0-9_./~][\w./~-]*)/gm;

/** The commands whose escalation actually changes system state. */
const SYSTEM_MODIFYING =
  /(?:\btee\b|\brm\b|\bpasswd\b|\bvisudo\b|\bmount\b|\bdd\b|\binsmod\b|\bmodprobe\b|\bsystemctl\b|\blaunchctl\b|\bcrontab\b|\bshutdown\b|\breboot\b|\/etc\/|sudoers|\b777\b|--dangerously)/i;

/** Build a `check` from a list of patterns, skipping defensive mentions. */
function guarded(patterns, rule, ctx) {
  const out = [];
  for (const re of patterns) {
    for (const { index, match } of eachMatch(re, ctx.text)) {
      if (inDefensiveContext(ctx.text, index, 400, match[0].length)) continue;
      out.push(findingAt(rule, ctx, index, match[0]));
      if (out.length >= 5) return out;
    }
  }
  return out;
}

export const executionRules = [
  {
    id: 'SG-EXEC-001',
    title: 'Remote code executed through a pipe',
    severity: 'critical',
    confidence: 'high',
    category: 'execution',
    owasp: 'AST05',
    description: 'Downloads a script from the network and executes it directly (curl | sh). The remote content is unpinned and unauditable.',
    remediation: 'Vendor the script, pin it to a checksum, and review it before running.',
    check(ctx) {
      return guarded(
        [
          /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|fish|python3?|perl|ruby|node|php)\b/gi,
          /\b(?:Invoke-Expression|iex)\b[^\n]{0,120}(?:DownloadString|Invoke-WebRequest|iwr|curl)/gi,
          /\biex\s*\(\s*(?:New-Object|iwr|Invoke-WebRequest)/gi,
        ],
        this,
        ctx
      );
    },
  },
  {
    id: 'SG-EXEC-002',
    title: 'Dynamic code evaluation',
    severity: 'high',
    confidence: 'medium',
    category: 'execution',
    owasp: 'AST05',
    description: 'Evaluates dynamically built code (eval/exec/Function), which hides what actually runs.',
    remediation: 'Avoid dynamic evaluation in skills. Write explicit, reviewable code.',
    patterns: [
      // Require an actual call: `eval(x)`, not the word "eval" or "eval (...) "
      // written out in prose or a documentation table.
      /\beval\(/g,
      /\bexec\s*\(\s*(?:[a-zA-Z_$][\w$]*\s*\+|compile\s*\(|base64|atob|__import__)/g,
      /\bnew\s+Function\s*\(/g,
      /\bos\.system\s*\(\s*[a-zA-Z_$][\w$]*\s*\+/g,
    ],
  },
  {
    id: 'SG-EXEC-003',
    title: 'Destructive filesystem command',
    severity: 'critical',
    confidence: 'high',
    category: 'execution',
    owasp: 'AST05',
    description: 'Deletes or overwrites data at a broad scope (root, home, wildcard, block devices).',
    remediation: 'Never target broad paths. Operate on explicit, user-named directories only.',
    check(ctx) {
      return guarded(
        [
          // Root, home or a bare wildcard, but not a named subdirectory such as
          // /workspace/reports or ./build.
          /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+\/(?=[\s'"`)\]}.,;:!?*]|$)/gi,
          /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+~\/?(?=[\s'"`)\]}.,;:!?*]|$)/gi,
          /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+\$\{?HOME\}?\/?(?=[\s'"`)\]}.,;:!?*]|$)/gi,
          /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+\*(?=[\s'"`)\].,;:!?]|$)/gi,
          /\bmkfs(?:\.\w+)?\b/gi,
          /\bdd\s+if=[^\n]{0,80}of=\/dev\//gi,
          />\s*\/dev\/(?:sd[a-z]|nvme\d|disk\d)/gi,
          /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/g,
          /\bshred\s+-[a-z]*\s+\/(?:etc|usr|var|home)/gi,
        ],
        this,
        ctx
      );
    },
  },
  {
    id: 'SG-EXEC-004',
    title: 'Privilege escalation',
    severity: 'medium',
    confidence: 'high',
    category: 'execution',
    owasp: 'AST05',
    description:
      'Runs a command with elevated privileges. A documented install step is an advisory; escalating to modify system state is serious.',
    remediation: 'Skills should run with the least privilege needed and never elevate silently.',
    check(ctx) {
      const out = [];
      const add = (index, match, severity) =>
        out.push(findingAt(this, ctx, index, match, { severity }));

      for (const { index, match } of eachMatch(SUDO_COMMAND, ctx.text)) {
        if (inDefensiveContext(ctx.text, index, 400, match[0].length)) continue;
        // `sudo tar` in an install guide is an advisory; `sudo tee /etc/...`,
        // `sudo rm` or `sudo systemctl` changes system state.
        const severity = SYSTEM_MODIFYING.test(lineAt(ctx.text, index)) ? 'high' : 'medium';
        add(index, match[0], severity);
        if (out.length >= 5) return out;
      }

      const fixed = [
        [/\bdoas\s+[a-zA-Z]/g, 'medium'],
        [/\bsu\s+-\s*(?:root)?\b/g, 'high'],
        [/\bchmod\s+-R\s+777\b/gi, 'high'],
        [/\bchown\s+-R\s+[^\n]*\s\/(?!tmp)/g, 'high'],
        [/\b(?:net\s+localgroup|runas\s+\/user:Administrator)/gi, 'high'],
      ];
      for (const [re, severity] of fixed) {
        for (const { index, match } of eachMatch(re, ctx.text)) {
          if (inDefensiveContext(ctx.text, index, 400, match[0].length)) continue;
          add(index, match[0], severity);
          if (out.length >= 5) return out;
        }
      }
      return out;
    },
  },
  {
    id: 'SG-EXEC-005',
    title: 'Persistence or system modification',
    severity: 'high',
    confidence: 'high',
    category: 'execution',
    owasp: 'AST05',
    description: 'Modifies shell profiles, cron, launch agents, system services or host files to survive the session.',
    remediation: 'A skill should not install persistence. Ask the user to opt in explicitly outside the skill.',
    check(ctx) {
      return guarded(
        [
          /(?:>>?|tee\s+-?a?)\s*[^\n]{0,60}(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|\.bash_login|\.config\/fish\/config\.fish)/gi,
          /\bcrontab\s+(?:-|-\s|\/|<<)/gi,
          /\/etc\/cron/gi,
          /\blaunchctl\s+(?:load|bootstrap|submit)/gi,
          /(?:systemctl|service)\s+(?:enable|start|restart)/gi,
          /\/etc\/(?:hosts|passwd|sudoers|shadow|fstab)/gi,
          /\bauthorized_keys\b/gi,
          /\b(?:reg\s+add|schtasks\s+\/create|New-Service)\b/gi,
          /\b(?:defaults\s+write|plutil\s+-[a-z]*)\b[^\n]{0,40}(?:LoginItems|LaunchAgents)/gi,
        ],
        this,
        ctx
      );
    },
  },
  {
    id: 'SG-EXEC-006',
    title: 'Destructive or history-rewriting git command',
    severity: 'high',
    confidence: 'medium',
    category: 'execution',
    owasp: 'AST05',
    description: 'Force-pushes, hard-resets or deletes git history, which can destroy the user\'s work irreversibly.',
    remediation: 'Avoid rewriting history. If needed, make it an explicit, confirmed step.',
    check(ctx) {
      return guarded(
        [
          /\bgit\s+push\b[^\n]*--force(?:-with-lease)?/gi,
          /\bgit\s+reset\s+--hard\b/gi,
          /\bgit\s+clean\s+-[a-z]*[dfx]/gi,
          /\bgit\s+(?:filter-branch|filter-repo)\b/gi,
          /\brm\s+-rf?\s+[^\n]{0,20}\.git\b/gi,
          /\bgit\s+branch\s+-D\b/gi,
        ],
        this,
        ctx
      );
    },
  },
  {
    id: 'SG-EXEC-007',
    title: 'Disables logging or security controls',
    severity: 'critical',
    confidence: 'high',
    category: 'execution',
    owasp: 'AST05',
    description: 'Turns off shell history, security policy or code-signing checks — behaviour whose only purpose is to avoid detection.',
    remediation: 'Remove. Never disable auditing or security enforcement from a skill.',
    patterns: [
      /\bset\s+\+o\s+history\b/gi,
      /\bHISTFILE\s*=\s*\/dev\/null/gi,
      /\bunset\s+HISTFILE\b/gi,
      /\bhistory\s+-c\b/gi,
      /\bspctl\s+--master-disable/gi,
      /\bcsrutil\s+disable\b/gi,
      /\bshutdown\s+-[a-z]*[h]\b/gi,
      /\b(?:ufw|firewall)\s+disable\b/gi,
      /\bnpm\s+config\s+set\s+[^\n]*ignore-scripts\s+false/gi,
    ],
  },
  {
    id: 'SG-EXEC-008',
    title: 'Process termination',
    severity: 'medium',
    confidence: 'low',
    category: 'execution',
    owasp: 'AST05',
    description: 'Kills processes. Sometimes legitimate, but easy to misuse; confirm scope before running.',
    remediation: 'Target a specific PID the user provided instead of matching process names.',
    patterns: [
      /\bpkill\s+-?[a-z]*\s+\w+/g,
      /\bkillall\s+\w+/g,
      /\btaskkill\s+\/IM/gi,
    ],
  },
];
