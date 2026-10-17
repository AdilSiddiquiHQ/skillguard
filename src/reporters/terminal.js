/**
 * Human-readable terminal reporter.
 */

import { isAtLeast, pluralize } from '../util.js';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  grey: '\x1b[90m',
  bgRed: '\x1b[41;97m',
  bgYellow: '\x1b[43;30m',
  bgGreen: '\x1b[42;30m',
};

const SEVERITY_COLOR = {
  critical: ANSI.bgRed,
  high: ANSI.red,
  medium: ANSI.yellow,
  low: ANSI.cyan,
  info: ANSI.grey,
};

const VERDICT = {
  fail: { label: 'FAIL', color: ANSI.red, mark: '✖' },
  review: { label: 'REVIEW', color: ANSI.yellow, mark: '▲' },
  pass: { label: 'PASS', color: ANSI.green, mark: '✔' },
};

function wrap(text, width, indent) {
  const words = String(text).split(/\s+/);
  const lines = [];
  let current = '';
  const pad = ' '.repeat(indent);
  for (const word of words) {
    if (current.length + word.length + 1 > width) {
      lines.push(current);
      current = word;
    } else {
      current = current ? `${current} ${word}` : word;
    }
  }
  if (current) lines.push(current);
  return lines.map((l) => pad + l).join('\n');
}

function scoreBar(score, colorCode, color) {
  const width = 20;
  const filled = Math.round((score / 100) * width);
  const on = color ? colorCode : '';
  const dim = color ? ANSI.dim : '';
  const reset = color ? ANSI.reset : '';
  return `${on}${'█'.repeat(filled)}${dim}${'░'.repeat(width - filled)}${reset}`;
}

export function renderTerminal(report, options = {}) {
  const color = options.color !== false;
  const c = (code, text) => (color ? `${code}${text}${ANSI.reset}` : text);
  const out = [];
  const verbose = Boolean(options.verbose);
  const maxPerSkill = verbose ? Infinity : 15;

  out.push('');
  out.push(
    `  ${c(ANSI.bold, 'SkillGuard')} ${c(ANSI.dim, report.version)}  ${c(ANSI.dim, `· ${report.ruleCount} rules · agent skills security scanner`)}`
  );
  out.push('');

  if (report.skills.length === 0) {
    out.push(`  ${c(ANSI.yellow, 'No skills found.')} ${c(ANSI.dim, 'A skill is a folder containing SKILL.md.')}`);
    out.push('');
    return out.join('\n');
  }

  for (const skill of report.skills) {
    const v = VERDICT[skill.verdict];
    const scoreColor = skill.verdict === 'fail' ? ANSI.red : skill.verdict === 'review' ? ANSI.yellow : ANSI.green;
    const header = `  ${c(v.color, v.mark)} ${c(ANSI.bold, skill.path)}`;
    const meta = `${v.label}  score ${skill.score}/100`;
    out.push(`${header}  ${c(ANSI.dim, '·')} ${c(scoreColor, meta)}`);
    out.push(`    ${scoreBar(skill.score, scoreColor, color)}`);

    if (skill.description) {
      out.push(`    ${c(ANSI.dim, skill.description)}`);
    }

    const shown = skill.findings.slice(0, maxPerSkill);
    for (const f of shown) {
      const sevColor = SEVERITY_COLOR[f.severity] || ANSI.grey;
      const label = c(sevColor, ` ${f.severity.toUpperCase()} `);
      const allowed = f.allowed ? c(ANSI.dim, ' (allowed)') : '';
      out.push('');
      out.push(`    ${label} ${c(ANSI.bold, f.title)}${allowed}`);
      out.push(
        `    ${c(ANSI.grey, `${f.file}:${f.line}:${f.column}`)}  ${c(ANSI.grey, f.ruleId)}${f.owasp ? `  ${c(ANSI.grey, f.owasp)}` : ''}`
      );
      if (f.match) out.push(`    ${c(ANSI.dim, '›')} ${c(ANSI.dim, f.match)}`);
      if (verbose && f.description) {
        out.push(wrap(f.description, 96, 6));
      }
      if (verbose && f.remediation) {
        out.push(`      ${c(ANSI.green, 'fix')}: ${f.remediation}`);
      }
    }

    if (skill.findings.length > shown.length) {
      out.push('');
      out.push(
        `    ${c(ANSI.dim, `… ${skill.findings.length - shown.length} more findings (use --verbose to show all)`)}`
      );
    }

    if (skill.findings.length === 0) {
      out.push(`    ${c(ANSI.green, 'No findings.')}`);
    }
    out.push('');
  }

  const s = report.summary;
  const threshold = report.failOn;
  const gateFails =
    Boolean(threshold) &&
    threshold !== 'none' &&
    report.skills.some((skill) =>
      skill.findings.some((f) => !f.allowed && isAtLeast(f.severity, threshold))
    );

  let result = 'PASS';
  if (gateFails) result = 'FAIL';
  else if (report.skills.some((skill) => skill.verdict !== 'pass')) result = 'REVIEW';

  const verdict = result === 'FAIL' ? c(ANSI.red, 'FAIL') : result === 'REVIEW' ? c(ANSI.yellow, 'REVIEW') : c(ANSI.green, 'PASS');
  const criticalLabel =
    s.counts.critical > 0
      ? c(ANSI.bgRed, ` ${s.counts.critical} critical `)
      : c(ANSI.grey, `${s.counts.critical} critical`);
  out.push(`  ${c(ANSI.bold, 'Summary')}`);
  out.push(
    `  ${pluralize(s.skills, 'skill')} · ${pluralize(s.findings, 'finding')} · ` +
      `${criticalLabel} ${c(ANSI.red, `${s.counts.high} high`)} ` +
      `${c(ANSI.yellow, `${s.counts.medium} medium`)} ${c(ANSI.cyan, `${s.counts.low} low`)}${s.counts.info ? ` ${c(ANSI.grey, `${s.counts.info} info`)}` : ''}`
  );
  out.push(`  ${c(ANSI.bold, 'result')} ${verdict}   ${c(ANSI.dim, `(fail-on: ${report.failOn})`)}`);
  out.push('');

  return out.join('\n');
}
