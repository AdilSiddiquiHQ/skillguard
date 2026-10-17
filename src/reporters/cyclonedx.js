/**
 * CycloneDX 1.6 SBOM reporter.
 *
 * Security teams already ingest CycloneDX from Trivy, Syft and friends. Making
 * agent skills first-class BOM components means a skill's files can be tracked,
 * signed and matched by the same pipelines as any other dependency. Findings
 * are emitted as `vulnerabilities` so they flow into existing dashboards.
 */

import { randomUUID } from 'node:crypto';

import { TOOL_NAME, VERSION } from '../version.js';

const SEVERITY = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };

export function renderCycloneDx(report, options = {}) {
  const timestamp = options.timestamp || report.generatedAt || new Date().toISOString();

  const components = [];
  const vulnerabilities = [];

  for (const skill of report.skills) {
    const skillRef = `skill:${skill.path}`;
    components.push({
      type: 'application',
      'bom-ref': skillRef,
      name: skill.name,
      version: undefined,
      description: skill.description || undefined,
      properties: [
        { name: 'skillguard:path', value: skill.path },
        { name: 'skillguard:kind', value: skill.kind || 'skill' },
        { name: 'skillguard:verdict', value: skill.verdict },
        { name: 'skillguard:score', value: String(skill.score) },
        ...(skill.evasions && skill.evasions.length
          ? [{ name: 'skillguard:evasions', value: skill.evasions.join(', ') }]
          : []),
      ],
    });

    for (const entry of skill.sbom || []) {
      components.push({
        type: 'file',
        'bom-ref': `file:${skill.path}/${entry.path}`,
        name: entry.path,
        properties: [
          { name: 'skillguard:skill', value: skill.path },
          { name: 'skillguard:bytes', value: String(entry.bytes) },
          { name: 'skillguard:binary', value: String(entry.binary) },
        ],
        hashes: entry.sha256 ? [{ alg: 'SHA-256', content: entry.sha256 }] : undefined,
      });
    }

    for (const f of skill.findings) {
      vulnerabilities.push({
        id: `${f.ruleId}:${f.file}:${f.line}`,
        source: { name: TOOL_NAME, url: 'https://github.com/AdilSiddiquiHQ/skillguard' },
        references: f.owasp
          ? [{ id: f.owasp, source: { name: 'OWASP Agentic Skills Top 10' } }]
          : undefined,
        ratings: [
          {
            severity: SEVERITY[f.severity] || 'unknown',
            method: 'other',
            justification: `confidence: ${f.confidence}`,
          },
        ],
        description: f.description,
        recommendation: f.remediation || undefined,
        affects: [{ ref: `file:${skill.path}/${f.file}` }],
        properties: [
          { name: 'skillguard:rule', value: f.ruleId },
          { name: 'skillguard:category', value: f.category },
          ...(f.evasion ? [{ name: 'skillguard:evasion', value: f.evasion }] : []),
          ...(f.derivedFrom ? [{ name: 'skillguard:recovered-from', value: String(f.derivedFrom.file) }] : []),
        ],
      });
    }
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: [
          {
            type: 'application',
            name: TOOL_NAME,
            version: VERSION,
            supplier: { name: 'SkillGuard' },
          },
        ],
      },
      component: {
        type: 'application',
        'bom-ref': 'root',
        name: 'agent-skills',
        properties: [
          { name: 'skillguard:targets', value: String(report.summary.skills) },
          { name: 'skillguard:rule-count', value: String(report.ruleCount) },
        ],
      },
    },
    components: pruneUndefined(components),
    vulnerabilities: pruneUndefined(vulnerabilities),
  };

  return bom;
}

/** Remove `undefined` values so the JSON stays clean. */
function pruneUndefined(value) {
  if (Array.isArray(value)) return value.map(pruneUndefined);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined) continue;
      out[k] = pruneUndefined(v);
    }
    return out;
  }
  return value;
}
