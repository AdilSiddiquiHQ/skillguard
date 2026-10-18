/**
 * GitHub Actions reporter.
 *
 * Emits workflow commands so findings appear inline on the pull-request diff
 * instead of only in the job log. See:
 * https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
 */

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'notice', info: 'notice' };

function escapeData(value) {
  return String(value).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(value) {
  return escapeData(value).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

export function renderGithub(report, options = {}) {
  const lines = [];
  const failOn = options.failOn || report.failOn || 'high';

  for (const skill of report.skills) {
    for (const f of skill.findings) {
      const level = f.baselined || f.allowed ? 'notice' : LEVEL[f.severity] || 'warning';
      const title = `${f.ruleId}: ${f.title}${f.evasion ? ` (evasion: ${f.evasion})` : ''}`;
      const message = f.derivedFrom
        ? `${f.description} [recovered from ${f.derivedFrom.file}${f.derivedFrom.entry ? `::${f.derivedFrom.entry}` : ''}]`
        : f.description;
      lines.push(
        `::${level} file=${escapeProperty(f.file)},line=${f.line},col=${f.column},title=${escapeProperty(title)}::${escapeData(message)}`
      );
    }
  }

  const s = report.summary;
  const verdict = s.failed > 0 ? 'FAIL' : s.review > 0 ? 'REVIEW' : 'PASS';
  lines.push('');
  lines.push(
    `::notice title=SkillSleuth::${verdict} — ${s.skills} target(s), ${s.findings} finding(s) ` +
      `(${s.counts.critical} critical, ${s.counts.high} high, ${s.counts.medium} medium). fail-on: ${failOn}`
  );

  if (report.baseline && report.baseline.applied) {
    lines.push(
      `::notice title=SkillSleuth baseline::${report.baseline.matched} baselined finding(s) excluded from the gate.`
    );
  }

  return `${lines.join('\n')}\n`;
}
