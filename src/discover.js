/**
 * Target discovery.
 *
 * A "skill" follows the open Agent Skills standard: a directory containing a
 * SKILL.md file (frontmatter + instructions), optionally with scripts and
 * resources beside it.
 *
 * Skills are not the only place an agent reads instructions or executes code,
 * so SkillGuard also discovers the adjacent, equally-trusted surfaces:
 *
 *   skill    a directory with SKILL.md
 *   plugin   plugin.json / .claude-plugin/plugin.json (hooks, commands, MCP)
 *   mcp      .mcp.json / claude_desktop_config.json and friends
 *   agents   CLAUDE.md / AGENTS.md / .cursorrules / .cursor/rules/*.mdc
 *
 * Hidden files are scanned on purpose: ignoring them was one of the documented
 * ways existing skill scanners were bypassed.
 */

import { readdirSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';

import { globToRegExp, looksBinary, matchesAny, readFileBufferSafe, sha256Buffer, toPosix } from './util.js';
import { parseFrontmatter } from './frontmatter.js';

export const SKILL_FILENAMES = ['skill.md', 'skill.markdown'];

const MAX_TEXT_BYTES = 5 * 1024 * 1024;

const DEFAULT_EXCLUDES = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'vendor',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  'target',
  'coverage',
];

export const MCP_CONFIG_NAMES = new Set([
  'mcp.json',
  'claude_desktop_config.json',
  'mcp_config.json',
  'server.json',
]);

export const AGENT_FILE_NAMES = new Set([
  'claude.md',
  'agents.md',
  'gemini.md',
  'cursorrules',
  'windsurfrules',
  'copilot-instructions.md',
  '.cursorrules',
  '.windsurfrules',
]);

function defaultExcludePatterns() {
  return DEFAULT_EXCLUDES.map((d) => globToRegExp(`**/${d}/**`));
}

function isSkillFileName(name) {
  return SKILL_FILENAMES.includes(name.toLowerCase());
}

function safeReaddir(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

function findSkillFile(dir) {
  for (const entry of safeReaddir(dir)) {
    if (entry.isFile() && isSkillFileName(entry.name)) {
      return join(dir, entry.name);
    }
  }
  return null;
}

/** Classify a non-skill file, or return null when it is not a known surface. */
export function classifySpecial(relPath) {
  const lower = toPosix(relPath).toLowerCase();
  const name = lower.split('/').pop();

  if (name === 'plugin.json' || lower.endsWith('.claude-plugin/plugin.json') || lower.endsWith('.claude-plugin/marketplace.json')) {
    return 'plugin';
  }
  if (name === '.mcp.json' || MCP_CONFIG_NAMES.has(name)) return 'mcp';
  if (lower.includes('/.mcp/') && lower.endsWith('.json')) return 'mcp';
  if (namesMatch(lower, AGENT_FILE_NAMES)) return 'agents';
  if (lower.endsWith('.mdc') && lower.includes('.cursor/rules/')) return 'agents';
  return null;
}

function namesMatch(lowerPath, set) {
  const name = lowerPath.split('/').pop();
  if (set.has(name)) return true;
  return false;
}

function collectFiles(dir, excludeRegexes, rootDir, out = []) {
  for (const entry of safeReaddir(dir)) {
    const abs = join(dir, entry.name);
    const rel = toPosix(relative(rootDir, abs));
    if (matchesAny(rel, excludeRegexes)) continue;

    if (entry.isDirectory()) {
      if (findSkillFile(abs) && abs !== dir) continue;
      collectFiles(abs, excludeRegexes, rootDir, out);
    } else if (entry.isFile()) {
      out.push(abs);
    }
  }
  return out;
}

/** Load one file into the internal representation. */
export function loadFileEntry(abs, rootDir) {
  const rel = toPosix(relative(rootDir, abs));
  const buf = readFileBufferSafe(abs);
  const bytes = buf ? buf.length : 0;

  let text = buf ? buf.toString('utf8') : null;
  const binary = buf === null || looksBinary(text);
  let magic = null;
  let sha256 = null;

  if (buf) {
    sha256 = sha256Buffer(buf);
    if (binary) {
      magic = buf.subarray(0, 8).toString('hex');
      text = '';
    } else if (bytes > MAX_TEXT_BYTES) {
      text = '';
    }
  }

  return {
    path: rel,
    abs,
    isSkillFile: false,
    binary,
    bytes,
    magic,
    text: text || '',
    sha256,
  };
}

function loadFiles(dir, skillFile, excludeRegexes, rootDir) {
  const paths = collectFiles(dir, excludeRegexes, rootDir);
  if (skillFile && !paths.includes(skillFile)) paths.unshift(skillFile);

  return paths.map((abs) => {
    const entry = loadFileEntry(abs, rootDir);
    entry.isSkillFile = abs === skillFile;
    return entry;
  });
}

function buildSkill(dir, skillFile, options, excludeRegexes) {
  const rootDir = resolve(options.cwd || process.cwd());
  const files = loadFiles(dir, skillFile, excludeRegexes, rootDir);
  const skillFileEntry = files.find((f) => f.isSkillFile) || null;
  const frontmatter = skillFileEntry ? parseFrontmatter(skillFileEntry.text) : parseFrontmatter('');

  const declaredName = typeof frontmatter.data.name === 'string' ? frontmatter.data.name : null;
  const dirName = basename(dir);

  return {
    kind: 'skill',
    name: declaredName || dirName,
    dir,
    relDir: toPosix(relative(rootDir, dir)) || '.',
    skillFile: skillFileEntry ? skillFileEntry.path : null,
    frontmatter: frontmatter.data,
    frontmatterPresent: frontmatter.present,
    frontmatterError: frontmatter.error,
    body: frontmatter.body,
    bodyOffset: frontmatter.bodyOffset,
    files,
  };
}

/** Build a single-file target (plugin manifest, MCP config, agent file). */
function buildLooseTarget(abs, kind, rootDir) {
  const file = loadFileEntry(abs, rootDir);
  const rel = file.path;
  const isMarkdown = /\.(?:md|markdown|mdc)$/i.test(rel);
  const frontmatter = isMarkdown ? parseFrontmatter(file.text) : { data: {}, present: false, body: file.text, bodyOffset: 0 };
  const name = frontmatter.data && typeof frontmatter.data.name === 'string' ? frontmatter.data.name : rel;

  return {
    kind,
    name,
    dir: dirname(abs),
    relDir: rel,
    skillFile: rel,
    frontmatter: frontmatter.data,
    frontmatterPresent: frontmatter.present,
    frontmatterError: frontmatter.error,
    body: frontmatter.body,
    bodyOffset: frontmatter.bodyOffset,
    files: [file],
  };
}

function walk(dir, options, excludeRegexes, skills, loose, seen, rootDir, insideSkill) {
  const entries = safeReaddir(dir);
  const childDirs = [];
  const skillFile = findSkillFile(dir);
  let nested = Boolean(insideSkill);

  if (skillFile) {
    const resolved = resolve(dir);
    if (!seen.has(resolved)) {
      seen.add(resolved);
      skills.push(buildSkill(resolved, skillFile, options, excludeRegexes));
    }
    // Keep descending so nested skills are discovered and scanned on their own.
    nested = true;
  }

  for (const entry of entries) {
    const abs = join(dir, entry.name);
    const rel = toPosix(relative(rootDir, abs));
    if (matchesAny(rel, excludeRegexes)) continue;

    if (entry.isDirectory()) {
      childDirs.push(abs);
    } else if (entry.isFile() && !nested) {
      const kind = classifySpecial(rel);
      if (kind && !seen.has(`loose:${abs}`)) {
        seen.add(`loose:${abs}`);
        loose.push(buildLooseTarget(resolve(abs), kind, rootDir));
      }
    }
  }

  for (const child of childDirs) {
    walk(child, options, excludeRegexes, skills, loose, seen, rootDir, nested);
  }
}

export function discoverSkills(paths, options = {}) {
  const cwd = options.cwd || process.cwd();
  const rootDir = resolve(cwd);
  const excludeRegexes = [...defaultExcludePatterns(), ...(options.exclude || []).map(globToRegExp)];
  const skills = [];
  const loose = [];
  const seen = new Set();
  const roots = (paths && paths.length ? paths : ['.']).map((p) => resolve(cwd, p));

  for (const root of roots) {
    let st;
    try {
      st = statSync(root);
    } catch {
      continue;
    }

    if (st.isFile()) {
      const name = basename(root);
      const rel = toPosix(relative(rootDir, root));
      if (isSkillFileName(name) || (options.all && name.toLowerCase().endsWith('.md'))) {
        const abs = resolve(root);
        if (seen.has(abs)) continue;
        seen.add(abs);
        const fileEntry = loadFiles(dirname(abs), abs, excludeRegexes, rootDir);
        const fm = parseFrontmatter(fileEntry.find((f) => f.isSkillFile)?.text || '');
        skills.push({
          kind: 'skill',
          name: fm.data.name || basename(dirname(abs)),
          dir: dirname(abs),
          relDir: toPosix(relative(rootDir, dirname(abs))) || '.',
          skillFile: toPosix(relative(rootDir, abs)),
          frontmatter: fm.data,
          frontmatterPresent: fm.present,
          frontmatterError: fm.error,
          body: fm.body,
          bodyOffset: fm.bodyOffset,
          files: fileEntry,
        });
        continue;
      }
      const kind = classifySpecial(rel);
      if (kind) {
        const abs = resolve(root);
        if (!seen.has(`loose:${abs}`)) {
          seen.add(`loose:${abs}`);
          loose.push(buildLooseTarget(abs, kind, rootDir));
        }
      }
      continue;
    }

    walk(root, { ...options, cwd }, excludeRegexes, skills, loose, seen, rootDir);
  }

  const all = [...skills, ...loose];
  all.sort((a, b) => a.relDir.localeCompare(b.relDir));
  return all;
}
