/**
 * Skill discovery. A "skill" follows the open Agent Skills standard:
 * a directory containing a SKILL.md file (frontmatter + instructions),
 * optionally with scripts and resources beside it.
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

function collectFiles(dir, excludeRegexes, rootDir, out = []) {
  for (const entry of safeReaddir(dir)) {
    const abs = join(dir, entry.name);
    const rel = toPosix(relative(rootDir, abs));
    if (matchesAny(rel, excludeRegexes)) continue;

    if (entry.isDirectory()) {
      // Do not descend into a nested skill; it is scanned on its own.
      if (findSkillFile(abs) && abs !== dir) continue;
      collectFiles(abs, excludeRegexes, rootDir, out);
    } else if (entry.isFile()) {
      out.push(abs);
    }
  }
  return out;
}

function loadFiles(dir, skillFile, excludeRegexes, rootDir) {
  const paths = collectFiles(dir, excludeRegexes, rootDir);
  if (skillFile && !paths.includes(skillFile)) paths.unshift(skillFile);

  return paths.map((abs) => {
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
      isSkillFile: abs === skillFile,
      binary,
      bytes,
      magic,
      text: text || '',
      sha256,
    };
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

function walk(dir, options, excludeRegexes, skills, seen) {
  const entries = safeReaddir(dir);
  const childDirs = [];
  const skillFile = findSkillFile(dir);

  if (skillFile) {
    const resolved = resolve(dir);
    if (!seen.has(resolved)) {
      seen.add(resolved);
      skills.push(buildSkill(resolved, skillFile, options, excludeRegexes));
    }
    return;
  }

  for (const entry of entries) {
    const abs = join(dir, entry.name);
    const rel = toPosix(relative(resolve(options.cwd || process.cwd()), abs));
    if (matchesAny(rel, excludeRegexes)) continue;
    if (entry.isDirectory()) childDirs.push(abs);
  }

  for (const child of childDirs) walk(child, options, excludeRegexes, skills, seen);
}

export function discoverSkills(paths, options = {}) {
  const cwd = options.cwd || process.cwd();
  const excludeRegexes = [...defaultExcludePatterns(), ...(options.exclude || []).map(globToRegExp)];
  const skills = [];
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
      if (isSkillFileName(name) || (options.all && name.toLowerCase().endsWith('.md'))) {
        const abs = resolve(root);
        if (seen.has(abs)) continue;
        seen.add(abs);
        const fileEntry = loadFiles(dirname(abs), abs, excludeRegexes, resolve(cwd));
        const frontmatter = parseFrontmatter(fileEntry.find((f) => f.isSkillFile)?.text || '');
        skills.push({
          name: frontmatter.data.name || basename(dirname(abs)),
          dir: dirname(abs),
          relDir: toPosix(relative(resolve(cwd), dirname(abs))) || '.',
          skillFile: toPosix(relative(resolve(cwd), abs)),
          frontmatter: frontmatter.data,
          frontmatterPresent: frontmatter.present,
          frontmatterError: frontmatter.error,
          body: frontmatter.body,
          bodyOffset: frontmatter.bodyOffset,
          files: fileEntry,
        });
      }
      continue;
    }

    walk(root, { ...options, cwd }, excludeRegexes, skills, seen);
  }

  skills.sort((a, b) => a.relDir.localeCompare(b.relDir));
  return skills;
}
