/**
 * Risk scoring. Deterministic, documented and dependency-free so results
 * are reproducible in CI and auditable by a human reviewer.
 */

import { CONFIDENCE_FACTOR, SEVERITY_WEIGHT, countBySeverity } from './util.js';

export const DEFAULT_THRESHOLDS = { review: 30, fail: 70 };

/**
 * score = min(100, sum(weight(severity) * confidenceFactor))
 */
export function scoreFindings(findings) {
  let total = 0;
  for (const f of findings) {
    const weight = SEVERITY_WEIGHT[f.severity] ?? 0;
    const factor = CONFIDENCE_FACTOR[f.confidence] ?? 1;
    total += weight * factor;
  }
  return Math.min(100, Math.round(total));
}

export function verdictFor(score, thresholds = DEFAULT_THRESHOLDS, findings = []) {
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasHighOrMedium = findings.some((f) => f.severity === 'high' || f.severity === 'medium');

  if (score >= thresholds.fail || hasCritical) return 'fail';
  if (score >= thresholds.review || hasHighOrMedium) return 'review';
  return 'pass';
}

export function summarize(skills, thresholds = DEFAULT_THRESHOLDS) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let baselined = 0;

  for (const skill of skills) {
    const skillCounts = skill.counts || countBySeverity(skill.findings.filter((f) => !f.allowed && !f.baselined));
    for (const key of Object.keys(counts)) counts[key] += skillCounts[key] || 0;
    baselined += skill.baselinedCount || 0;
  }

  const findings = counts.critical + counts.high + counts.medium + counts.low + counts.info;
  const worstSkillScore = skills.reduce((max, s) => Math.max(max, s.score), 0);
  const failed = skills.filter((s) => s.verdict === 'fail').length;
  const review = skills.filter((s) => s.verdict === 'review').length;
  const passed = skills.filter((s) => s.verdict === 'pass').length;

  return {
    skills: skills.length,
    findings,
    counts,
    baselined,
    worstSkillScore,
    failed,
    review,
    passed,
    thresholds,
  };
}
