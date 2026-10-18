/**
 * Baseline / incremental scanning.
 *
 * Adopting a scanner on an existing repository is painful when the first run
 * reports hundreds of pre-existing findings. A baseline records the findings
 * you have acknowledged, so CI fails only on what is *new*. Baselined
 * findings stay visible in the report but no longer affect the score or gate.
 */

import { existsSync, readFileSync } from 'node:fs';

import { sha256 } from './util.js';
import { scoreFindings, verdictFor, summarize } from './score.js';
import { countBySeverity } from './util.js';

/**
 * A stable identity for a finding. Deliberately line-independent: adding a
 * comment above a finding must not make it look like a new issue.
 */
export function fingerprint(finding) {
  const snippet = String(finding.match || '').replace(/\s+/g, ' ').trim().toLowerCase();
  const material = snippet
    ? `${finding.ruleId}|${finding.file}|${snippet}`
    : `${finding.ruleId}|${finding.file}|${finding.line}`;
  return sha256(material).slice(0, 32);
}

export function computeBaseline(report, options = {}) {
  const findings = {};
  for (const skill of report.skills) {
    for (const f of skill.findings) {
      if (f.allowed) continue;
      findings[fingerprint(f)] = {
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        file: f.file,
        skill: skill.path,
      };
    }
  }
  return {
    kind: 'skillsleuth-baseline',
    version: 1,
    tool: report.tool,
    toolVersion: report.version,
    generatedAt: new Date().toISOString(),
    root: options.root || report.root || null,
    count: Object.keys(findings).length,
    findings,
  };
}

export function loadBaseline(path) {
  if (!path || !existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    const map = parsed && typeof parsed.findings === 'object' ? parsed.findings : {};
    return { keys: new Set(Object.keys(map)), meta: parsed };
  } catch (err) {
    throw new Error(`Failed to read baseline at ${path}: ${err.message}`);
  }
}

/**
 * Return a copy of the report where baselined findings are marked and
 * excluded from scoring, verdicts and the summary.
 */
export function applyBaseline(report, baseline, thresholds) {
  if (!baseline) return report;
  const limits = thresholds || report.thresholds;

  const skills = report.skills.map((skill) => {
    const findings = skill.findings.map((f) => {
      const known = !f.allowed && baseline.keys.has(fingerprint(f));
      return known ? { ...f, baselined: true } : f;
    });

    const active = findings.filter((f) => !f.allowed && !f.baselined);
    const score = scoreFindings(active);
    const verdict = verdictFor(score, limits, active);

    return {
      ...skill,
      findings,
      score,
      verdict,
      counts: countBySeverity(active),
      baselinedCount: findings.filter((f) => f.baselined).length,
    };
  });

  return {
    ...report,
    skills,
    summary: summarize(skills, limits),
    baseline: {
      applied: true,
      count: baseline.keys.size,
      matched: skills.reduce((n, s) => n + (s.baselinedCount || 0), 0),
    },
  };
}
