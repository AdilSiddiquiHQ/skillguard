/**
 * Scan orchestration: discover -> run rules -> dedupe -> score -> report.
 */

import { discoverSkills } from './discover.js';
import { ALL_RULES, RULES_BY_ID, ruleCount } from './rules/index.js';
import { runPatterns } from './rules/helpers.js';
import { buildLineStarts, compareSeverity, countBySeverity, isAtLeast, matchesAny, globToRegExp } from './util.js';
import { scoreFindings, verdictFor, summarize } from './score.js';
import { TOOL_NAME, VERSION } from './version.js';

function buildContext(skill, file) {
  return {
    skill,
    file,
    text: file.text || '',
    lineStarts: buildLineStarts(file.text || ''),
    frontmatter: skill.frontmatter || {},
    frontmatterPresent: Boolean(skill.frontmatterPresent),
    isSkillFile: Boolean(file.isSkillFile),
  };
}

function shouldSkipRule(rule, file) {
  if (rule.category === 'assets') return file.isSkillFile;
  if (rule.targets === 'skill') return !file.isSkillFile;
  return false;
}

function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    // One finding per rule per line keeps reports readable.
    const key = `${f.ruleId}|${f.file}|${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

export function scanSkill(skill, config) {
  const findings = [];
  const ignore = new Set(config.ignore || []);
  const allowRegexes = (config.allow || []).map(globToRegExp);
  const maxPerRule = config.maxFindingsPerRulePerFile || 5;

  for (const file of skill.files) {
    const hasText = Boolean(file.text);
    for (const rule of ALL_RULES) {
      if (ignore.has(rule.id)) continue;
      if (shouldSkipRule(rule, file)) continue;

      const needsText = typeof rule.check === 'function' || Array.isArray(rule.patterns);
      if (needsText && !hasText && rule.category !== 'assets') continue;

      const ctx = buildContext(skill, file);
      let produced = [];

      if (typeof rule.check === 'function') {
        try {
          produced = rule.check(ctx) || [];
        } catch {
          produced = [];
        }
      } else if (Array.isArray(rule.patterns)) {
        produced = runPatterns(rule, ctx, maxPerRule);
      }

      for (const f of produced) {
        f.allowed = allowRegexes.length > 0 && matchesAny(f.file, allowRegexes);
        findings.push(f);
      }
    }
  }

  const unique = dedupe(findings).sort((a, b) => {
    const bySeverity = compareSeverity(a.severity, b.severity);
    if (bySeverity !== 0) return bySeverity;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  const scoreable = unique.filter((f) => !f.allowed);
  const score = scoreFindings(scoreable);
  const verdict = verdictFor(score, config.thresholds, scoreable);

  return {
    name: skill.name,
    path: skill.relDir,
    skillFile: skill.skillFile,
    description:
      typeof skill.frontmatter?.description === 'string' ? skill.frontmatter.description : null,
    fileCount: skill.files.length,
    score,
    verdict,
    counts: countBySeverity(scoreable),
    findings: unique,
    sbom: skill.files.map((f) => ({
      path: f.path,
      sha256: f.sha256,
      bytes: f.bytes,
      binary: f.binary,
    })),
  };
}

export function scan(paths, options = {}) {
  const cwd = options.cwd || process.cwd();
  const config = options.config;
  const skills = discoverSkills(paths, {
    cwd,
    exclude: config.exclude,
    all: options.all,
  });

  const results = skills.map((skill) => scanSkill(skill, config));
  const summary = summarize(results, config.thresholds);

  return {
    tool: TOOL_NAME,
    version: VERSION,
    generatedAt: new Date().toISOString(),
    root: cwd,
    ruleCount: ruleCount(),
    thresholds: config.thresholds,
    failOn: config.failOn,
    summary,
    skills: results,
  };
}

/**
 * Decide whether the run should fail the process.
 * Fails when any non-allowed finding meets `failOn`, or when `minScore` is set
 * and any skill meets it.
 */
export function evaluateGate(report, config) {
  const offenders = [];

  for (const skill of report.skills) {
    const failing = skill.findings.filter(
      (f) => !f.allowed && isAtLeast(f.severity, config.failOn)
    );
    const scoreBreach =
      typeof config.minScore === 'number' && skill.score >= config.minScore && skill.findings.length > 0;

    if (failing.length > 0 || scoreBreach) {
      offenders.push({ skill, failing, scoreBreach });
    }
  }

  return { failed: offenders.length > 0, offenders };
}

export { RULES_BY_ID, ALL_RULES };
