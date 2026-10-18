/**
 * SARIF 2.1.0 reporter, so results show up in GitHub code scanning.
 */

import { ALL_RULES } from '../rules/index.js';
import { VERSION } from '../version.js';

const LEVEL = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

export function renderSarif(report) {
  const rules = ALL_RULES.map((rule) => ({
    id: rule.id,
    name: rule.id,
    shortDescription: { text: rule.title },
    fullDescription: { text: rule.description || rule.title },
    help: {
      text: rule.remediation ? `${rule.description} Fix: ${rule.remediation}` : rule.description,
    },
    properties: {
      category: rule.category,
      severity: rule.severity,
      owasp: rule.owasp || null,
      tags: [rule.category, rule.severity, ...(rule.owasp ? [rule.owasp] : [])],
    },
  }));

  const results = [];
  for (const skill of report.skills) {
    for (const f of skill.findings) {
      results.push({
        ruleId: f.ruleId,
        level: LEVEL[f.severity] || 'note',
        message: {
          text: `${f.title} in ${f.file}:${f.line}${f.match ? ` — ${f.match}` : ''}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.line, startColumn: f.column },
            },
          },
        ],
        properties: {
          skill: skill.path,
          severity: f.severity,
          confidence: f.confidence,
          owasp: f.owasp,
          allowed: Boolean(f.allowed),
        },
        suppressions: f.allowed ? [{ kind: 'external', justification: 'Allowed by .skillsleuth config' }] : undefined,
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SkillSleuth',
            version: VERSION,
            informationUri: 'https://github.com/AdilSiddiquiHQ/skillsleuth',
            rules,
          },
        },
        results,
      },
    ],
  };
}
