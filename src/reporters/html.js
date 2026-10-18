/**
 * Self-contained HTML report.
 *
 * A single file with inline CSS and no network requests: easy to attach to a
 * CI artifact, open from the filesystem, or screenshot for a README. Reports
 * are read by humans who did not write the skill, so this is intentionally
 * more legible than the terminal output.
 */

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export function renderHtml(report, options = {}) {
  const title = options.title || 'SkillSleuth report';
  const skills = report.skills || [];
  const s = report.summary || { counts: {}, skills: 0, findings: 0 };
  const generated = report.generatedAt || new Date().toISOString();

  const verdict = s.failed > 0 ? 'fail' : s.review > 0 ? 'review' : 'pass';
  const verdictLabel = { fail: 'FAIL', review: 'REVIEW', pass: 'PASS' }[verdict];

  const cards = [
    ['Targets', s.skills],
    ['Findings', s.findings],
    ['Critical', s.counts.critical || 0],
    ['High', s.counts.high || 0],
    ['Medium', s.counts.medium || 0],
    ['Worst score', `${s.worstSkillScore ?? 0}/100`],
  ];

  const sections = skills
    .map((skill) => {
      const evasions = (skill.evasions || []).length
        ? `<div class="evasions">evasion detected: ${skill.evasions.map((e) => `<span class="tag">${esc(e)}</span>`).join(' ')}</div>`
        : '';
      const findings = skill.findings.length
        ? skill.findings.map((f) => renderFinding(f)).join('\n')
        : '<p class="clean">No findings.</p>';
      return `
    <section class="target">
      <header class="target-head">
        <div>
          <h2>${esc(skill.path)} <span class="kind">${esc(skill.kind || 'skill')}</span></h2>
          ${skill.description ? `<p class="desc">${esc(skill.description)}</p>` : ''}
        </div>
        <div class="target-meta">
          <span class="pill ${esc(skill.verdict)}">${esc(skill.verdict.toUpperCase())}</span>
          <span class="score">${skill.score}<small>/100</small></span>
          <span class="files">${skill.fileCount} file(s)</span>
        </div>
      </header>
      ${evasions}
      <div class="findings">${findings}</div>
    </section>`;
    })
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
    --dim: #8b949e; --crit: #f85149; --high: #ff7b72; --med: #d29922;
    --low: #58a6ff; --info: #8b949e; --pass: #3fb950;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 40px 24px 80px; }
  h1 { font-size: 26px; margin: 0; letter-spacing: -0.02em; }
  .sub { color: var(--dim); margin-top: 6px; font-size: 13px; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 12px; margin: 28px 0 36px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .card .k { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
  .card .v { font-size: 24px; font-weight: 650; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .verdict { display: inline-block; padding: 5px 12px; border-radius: 999px; font-weight: 700;
    font-size: 13px; letter-spacing: 0.04em; }
  .verdict.pass { background: rgba(63,185,80,0.15); color: var(--pass); border: 1px solid rgba(63,185,80,0.4); }
  .verdict.review { background: rgba(210,153,34,0.15); color: var(--med); border: 1px solid rgba(210,153,34,0.4); }
  .verdict.fail { background: rgba(248,81,73,0.15); color: var(--crit); border: 1px solid rgba(248,81,73,0.4); }
  .target { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    margin-bottom: 20px; overflow: hidden; }
  .target-head { display: flex; justify-content: space-between; gap: 16px; padding: 18px 20px;
    border-bottom: 1px solid var(--border); align-items: flex-start; }
  h2 { font-size: 16px; margin: 0; font-family: var(--mono); font-weight: 600; }
  .kind { color: var(--dim); font-size: 12px; font-family: inherit; font-weight: 400; }
  .desc { color: var(--dim); font-size: 13px; margin: 6px 0 0; max-width: 620px; }
  .target-meta { display: flex; align-items: center; gap: 14px; white-space: nowrap; }
  .score { font-size: 20px; font-weight: 700; font-variant-numeric: tabular-nums; }
  .score small { color: var(--dim); font-size: 12px; font-weight: 400; }
  .files { color: var(--dim); font-size: 12px; }
  .pill { padding: 3px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; }
  .pill.pass { background: rgba(63,185,80,0.15); color: var(--pass); }
  .pill.review { background: rgba(210,153,34,0.15); color: var(--med); }
  .pill.fail { background: rgba(248,81,73,0.15); color: var(--crit); }
  .evasions { padding: 10px 20px; background: rgba(248,81,73,0.07); border-bottom: 1px solid var(--border);
    color: var(--high); font-size: 13px; }
  .tag { font-family: var(--mono); font-size: 12px; background: rgba(255,255,255,0.06);
    border-radius: 4px; padding: 1px 6px; margin-left: 4px; }
  .findings { padding: 8px 20px 16px; }
  .finding { border-bottom: 1px solid var(--border); padding: 14px 0; }
  .finding:last-child { border-bottom: none; }
  .finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .sev { font-size: 11px; font-weight: 700; letter-spacing: 0.05em; padding: 2px 8px; border-radius: 4px; }
  .sev.critical { background: var(--crit); color: #fff; }
  .sev.high { background: rgba(255,123,114,0.2); color: var(--high); }
  .sev.medium { background: rgba(210,153,34,0.2); color: var(--med); }
  .sev.low { background: rgba(88,166,255,0.15); color: var(--low); }
  .sev.info { background: rgba(139,148,158,0.15); color: var(--info); }
  .finding h3 { font-size: 14px; margin: 0; font-weight: 600; }
  .loc { color: var(--dim); font-size: 12px; font-family: var(--mono); margin-top: 6px; }
  .match { font-family: var(--mono); font-size: 12.5px; color: var(--text); background: #0b0f14;
    border: 1px solid var(--border); border-radius: 6px; padding: 6px 10px; margin-top: 8px;
    overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
  .body { color: var(--dim); font-size: 13px; margin-top: 8px; }
  .fix { color: var(--pass); font-size: 13px; margin-top: 6px; }
  .clean { color: var(--pass); font-size: 13px; }
  .baseline { background: rgba(88,166,255,0.12); color: var(--low); border: 1px solid rgba(88,166,255,0.3);
    border-radius: 8px; padding: 10px 14px; font-size: 13px; margin-bottom: 20px; }
  footer { color: var(--dim); font-size: 12px; text-align: center; margin-top: 40px; }
  code { font-family: var(--mono); }
</style>
</head>
<body>
  <div class="wrap">
    <h1>SkillSleuth <span class="verdict ${verdict}">${verdictLabel}</span></h1>
    <p class="sub">${esc(report.tool)} ${esc(report.version)} · ${report.ruleCount} rules · generated ${esc(generated)} · fail-on ${esc(report.failOn || 'high')}</p>

    <div class="summary">
      ${cards.map(([k, v]) => `<div class="card"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`).join('')}
    </div>

    ${report.baseline && report.baseline.applied
      ? `<div class="baseline">Baseline applied: ${report.baseline.matched} of ${report.baseline.count} known finding(s) excluded from the gate.</div>`
      : ''}

    ${sections || '<p class="clean">No targets found.</p>'}

    <footer>Generated by SkillSleuth · github.com/AdilSiddiquiHQ/skillsleuth</footer>
  </div>
</body>
</html>
`;
}

function renderFinding(f) {
  const bits = [
    `<span class="sev ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span>`,
    f.baselined ? '<span class="sev info">BASELINED</span>' : '',
    f.allowed ? '<span class="sev info">ALLOWED</span>' : '',
    f.evasion ? `<span class="sev high">EVASION: ${esc(f.evasion)}</span>` : '',
  ].filter(Boolean);

  const loc = [f.file, f.line, f.column].filter((v) => v !== undefined && v !== null).join(':');
  const recovered = f.derivedFrom
    ? `<div class="loc">recovered from ${esc(f.derivedFrom.file)}${f.derivedFrom.entry ? ` :: ${esc(f.derivedFrom.entry)}` : ''}</div>`
    : '';

  return `
      <article class="finding">
        <div class="finding-head">${bits.join('')}<h3>${esc(f.title)}</h3></div>
        <div class="loc">${esc(loc)} · ${esc(f.ruleId)}${f.owasp ? ` · ${esc(f.owasp)}` : ''}</div>
        ${f.match ? `<div class="match">${esc(f.match)}</div>` : ''}
        ${f.description ? `<div class="body">${esc(f.description)}</div>` : ''}
        ${f.remediation ? `<div class="fix">fix: ${esc(f.remediation)}</div>` : ''}
        ${recovered}
      </article>`;
}

export { SEVERITY_ORDER };
