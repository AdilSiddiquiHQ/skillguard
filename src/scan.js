/**
 * Scan orchestration: discover -> build views -> run rules -> dedupe -> score.
 *
 * Every text file is examined through several *views* so that obfuscation and
 * packaging cannot hide a payload:
 *
 *   raw           the bytes as written
 *   deobfuscated  zero-width stripped, homoglyphs folded, escapes decoded
 *   decoded:*     base64 / hex / percent payloads extracted and scanned
 *   archive:*     entries inside zip / docx / xlsx / pptx / jar containers
 *
 * Views carry an index map back to the original text so reported line and
 * column numbers always point at the real file.
 */

import { discoverSkills } from './discover.js';
import { ALL_RULES, RULES_BY_ID, ruleCount } from './rules/index.js';
import { runPatterns } from './rules/helpers.js';
import { buildLineStarts, compareSeverity, countBySeverity, isAtLeast, matchesAny, globToRegExp, posAt } from './util.js';
import { scoreFindings, verdictFor, summarize } from './score.js';
import { deobfuscate, extractEncodedPayloads } from './normalize.js';
import { extractStrings, isArchivePath, isBinaryArtifactPath, readArchiveFile } from './archive.js';
import { readFileBufferSafe } from './util.js';
import { TOOL_NAME, VERSION } from './version.js';

/** Files larger than this are scanned raw-only; they are not skills. */
const MAX_DERIVED_TEXT = 2 * 1024 * 1024;

function makeView(kind, text, fileLabel, extra = {}) {
  const lineStarts = buildLineStarts(text);
  const derivedFrom = extra.derivedFrom || null;
  return {
    kind,
    name: extra.name || kind,
    text,
    lineStarts,
    fileLabel,
    derivedFrom,
    entryName: extra.entryName || null,
    evasion: extra.evasion || null,
    map: extra.map || null,
    sourceLineStarts: extra.sourceLineStarts || lineStarts,
    posFor(index) {
      if (extra.map) return posAt(extra.sourceLineStarts, extra.map[index] ?? index);
      return posAt(lineStarts, index);
    },
  };
}

/**
 * Build the scan views for a text file: raw, deobfuscated and any decoded
 * payloads. Archives are handled separately because they need the raw bytes.
 */
export function buildViews(file) {
  const views = [];
  const rawStarts = buildLineStarts(file.text || '');
  views.push(makeView('raw', file.text || '', file.path, { sourceLineStarts: rawStarts }));

  if (!file.text) return views;

  if (file.text.length > MAX_DERIVED_TEXT) return views;

  const deo = deobfuscate(file.text);
  if (deo.text !== file.text) {
    views.push(
      makeView('deobfuscated', deo.text, file.path, {
        name: `deobfuscated (${deo.tricks.join(', ')})`,
        evasion: deo.tricks.join(', '),
        map: deo.map,
        sourceLineStarts: rawStarts,
      })
    );
  }

  for (const payload of extractEncodedPayloads(file.text)) {
    const suffix = payload.parent ? ` via ${payload.parent}` : '';
    views.push(
      makeView('decoded', payload.decoded, `${file.path} (${payload.encoding}${suffix})`, {
        name: `decoded:${payload.encoding}`,
        evasion: payload.encoding,
        derivedFrom: {
          file: file.path,
          line: posAt(rawStarts, payload.index).line,
          encoding: payload.encoding,
        },
      })
    );
  }

  return views;
}

/** Views for entries inside an archive or Office document. */
export function buildArchiveViews(file) {
  if (!isArchivePath(file.path) || !file.abs) return [];
  const out = [];
  for (const entry of readArchiveFile(file.abs, { maxEntries: 128 })) {
    if (!entry.text) continue;
    out.push(
      makeView('archive', entry.text, `${file.path}::${entry.name}`, {
        name: `archive:${entry.name}`,
        entryName: entry.name,
        derivedFrom: { file: file.path, entry: entry.name },
      })
    );
    if (out.length >= 64) break;
  }
  return out;
}

/** Attach precomputed analysis (parsed JSON, binary strings) to file records. */
function prepareFiles(skill) {
  for (const file of skill.files) {
    if (!file.json && typeof file.text === 'string' && /\.json$/i.test(file.path) && file.text.trim()) {
      try {
        file.json = JSON.parse(file.text);
      } catch {
        file.json = null;
      }
    }
    if (!file.strings && isBinaryArtifactPath(file.path) && file.abs) {
      file.strings = extractStrings(readFileBufferSafe(file.abs));
    }
  }
  return skill;
}

function shouldSkipRule(rule, file) {
  if (rule.category === 'assets') return file.isSkillFile;
  if (rule.targets === 'skill') return !file.isSkillFile;
  return false;
}

/** Categories whose rules reason about file metadata, not text content. */
const FILE_LEVEL_CATEGORIES = new Set(['assets', 'artifacts']);

function viewAllowed(rule, view) {
  if (!rule.views || rule.views.length === 0) return true;
  return rule.views.includes(view.kind);
}

function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = `${f.ruleId}|${f.file}|${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

function skillContext(skill) {
  const label = skill.skillFile || skill.relDir;
  return {
    skill,
    files: skill.files,
    text: '',
    lineStarts: [0],
    frontmatter: skill.frontmatter || {},
    frontmatterPresent: Boolean(skill.frontmatterPresent),
    isSkillFile: false,
    view: { kind: 'skill', name: 'skill' },
    fileLabel: label,
    file: { path: label, isSkillFile: false },
    evasion: null,
    derivedFrom: null,
    posFor: () => ({ line: 1, column: 1 }),
  };
}

export function scanSkill(skill, config, rules = ALL_RULES) {
  prepareFiles(skill);

  const findings = [];
  const ignore = new Set(config.ignore || []);
  const allowRegexes = (config.allow || []).map(globToRegExp);
  const maxPerRule = config.maxFindingsPerRulePerFile || 5;
  const evasions = new Set();

  // Rules that reason about the whole skill rather than one file.
  const skillCtx = skillContext(skill);
  for (const rule of rules) {
    if (!rule.perSkill || ignore.has(rule.id)) continue;
    let produced = [];
    try {
      produced = rule.check(skillCtx) || [];
    } catch {
      produced = [];
    }
    for (const f of produced) {
      f.allowed = allowRegexes.length > 0 && matchesAny(f.file, allowRegexes);
      findings.push(f);
    }
  }

  for (const file of skill.files) {
    const views = [...buildViews(file), ...buildArchiveViews(file)];

    for (const view of views) {
      if (view.evasion) evasions.add(view.evasion);
      const hasText = Boolean(view.text);
      if (hasText && !view.derivedFrom && view.kind === 'deobfuscated') evasions.add(view.evasion);

      const ctx = {
        skill,
        file,
        text: view.text,
        lineStarts: view.lineStarts,
        frontmatter: skill.frontmatter || {},
        frontmatterPresent: Boolean(skill.frontmatterPresent),
        isSkillFile: Boolean(file.isSkillFile),
        view: { kind: view.kind, name: view.name },
        fileLabel: view.fileLabel,
        entryName: view.entryName,
        evasion: view.evasion,
        derivedFrom: view.derivedFrom,
        posFor: view.posFor,
      };

      for (const rule of rules) {
        if (rule.perSkill) continue;
        if (ignore.has(rule.id)) continue;
        if (shouldSkipRule(rule, file)) continue;
        if (!viewAllowed(rule, view)) continue;

        const needsText = typeof rule.check === 'function' || Array.isArray(rule.patterns);
        if (needsText && !hasText && !FILE_LEVEL_CATEGORIES.has(rule.category)) continue;

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
  }

  const overrides = config.severityOverrides || {};
  const unique = dedupe(findings)
    .map((f) => (overrides[f.ruleId] ? { ...f, severity: overrides[f.ruleId], overridden: true } : f))
    .sort((a, b) => {
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
    kind: skill.kind || 'skill',
    path: skill.relDir,
    skillFile: skill.skillFile,
    description:
      typeof skill.frontmatter?.description === 'string' ? skill.frontmatter.description : null,
    fileCount: skill.files.length,
    score,
    verdict,
    counts: countBySeverity(scoreable),
    evasions: [...evasions].sort(),
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

  const rules = [...ALL_RULES, ...(config.policyRules || [])];
  const results = skills.map((skill) => scanSkill(skill, config, rules));
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
    const active = skill.findings.filter((f) => !f.allowed && !f.baselined);
    const failing = active.filter((f) => isAtLeast(f.severity, config.failOn));
    const scoreBreach =
      typeof config.minScore === 'number' && skill.score >= config.minScore && active.length > 0;

    if (failing.length > 0 || scoreBreach) {
      offenders.push({ skill, failing, scoreBreach });
    }
  }

  return { failed: offenders.length > 0, offenders };
}

export { RULES_BY_ID, ALL_RULES };
