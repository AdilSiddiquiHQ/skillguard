#!/usr/bin/env node
/**
 * Measure precision on a set of skill directories.
 *
 *   node scripts/measure-precision.js <path...> [--json] [--max-per-skill N]
 *
 * A scanner is only kept if it stays quiet on legitimate work. The number that
 * decides that is *findings per skill* on known-clean repositories, so this
 * script reports it directly, alongside the rules that produced the findings.
 *
 * The README numbers were produced with it against public skill repositories:
 *
 *   git clone --depth 1 https://github.com/anthropics/skills
 *   git clone --depth 1 https://github.com/mattpocock/skills
 *   git clone --depth 1 https://github.com/vercel-labs/skills
 *   node scripts/measure-precision.js anthropics_skills mattpocock_skills vercel-labs_skills
 *
 * Exit code is always 0: this is a measurement, not a gate.
 */

import { existsSync } from 'node:fs';

import { scan } from '../src/scan.js';
import { DEFAULT_CONFIG } from '../src/config.js';

const argv = process.argv.slice(2);
const asJson = argv.includes('--json');
const maxArg = argv.find((a) => a.startsWith('--max-per-skill='));
const maxPerSkill = maxArg ? Number(maxArg.split('=')[1]) : null;
const paths = argv.filter((a) => !a.startsWith('--'));

if (paths.length === 0) {
  console.error('usage: node scripts/measure-precision.js <path...> [--json] [--max-per-skill=N]');
  process.exit(2);
}

const missing = paths.filter((p) => !existsSync(p));
if (missing.length > 0) {
  console.error(`not found: ${missing.join(', ')}`);
  process.exit(2);
}

const report = scan(paths, { config: DEFAULT_CONFIG });
const findings = report.skills.flatMap((skill) =>
  skill.findings.map((f) => ({ ...f, skill: skill.name }))
);

const byRule = new Map();
for (const f of findings) {
  const entry = byRule.get(f.ruleId) || { ruleId: f.ruleId, severity: f.severity, title: f.title, count: 0 };
  entry.count += 1;
  byRule.set(f.ruleId, entry);
}
const rules = [...byRule.values()].sort((a, b) => b.count - a.count);

const counts = report.summary.counts;
const targets = report.skills.length;
const perSkill = targets > 0 ? report.summary.findings / targets : 0;
const severe = counts.critical + counts.high;

if (asJson) {
  console.log(
    JSON.stringify(
      {
        paths,
        targets,
        findings: report.summary.findings,
        counts,
        findingsPerSkill: Number(perSkill.toFixed(2)),
        severe,
        rules,
      },
      null,
      2
    )
  );
} else {
  console.log(`targets:           ${targets}`);
  console.log(`findings:          ${report.summary.findings}`);
  console.log(`findings / skill:  ${perSkill.toFixed(2)}`);
  console.log(
    `severity:          ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info`
  );
  if (rules.length > 0) {
    console.log('\nby rule:');
    for (const r of rules) {
      console.log(`  ${String(r.count).padStart(4)}  ${r.severity.padEnd(8)} ${r.ruleId.padEnd(13)} ${r.title}`);
    }
  }
  if (maxPerSkill !== null) {
    const over = report.skills
      .map((s) => ({ name: s.name, n: s.findings.length }))
      .filter((s) => s.n > maxPerSkill);
    if (over.length > 0) {
      console.log(`\nskills over ${maxPerSkill} findings:`);
      for (const s of over) console.log(`  ${s.n}  ${s.name}`);
    }
  }
  console.log(`\nresult: ${severe === 0 ? 'quiet on this corpus' : `${severe} critical/high finding(s) to review`}`);
}
