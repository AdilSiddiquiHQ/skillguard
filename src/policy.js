/**
 * Policy as code.
 *
 * Teams need to encode their own house rules without forking the scanner.
 * A project can declare extra rules and adjust built-in severities directly
 * in `.skillguard.yml`; both are compiled into the same rule shape the engine
 * already understands.
 */

import { SEVERITIES, compareSeverity } from './util.js';

const SEVERITY_SET = new Set(SEVERITIES);

function pick(object, ...names) {
  for (const name of names) {
    if (object[name] !== undefined && object[name] !== null) return object[name];
  }
  return undefined;
}

function asArray(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Compile `rules:` entries from the config into rule objects.
 * Unknown severities fall back to `medium` rather than failing the scan.
 */
export function compilePolicyRules(raw) {
  const entries = asArray(pick(raw, 'rules', 'custom-rules', 'customRules'));
  const out = [];

  entries.forEach((entry, index) => {
    if (!entry || typeof entry !== 'object') return;
    const patterns = asArray(pick(entry, 'pattern', 'patterns', 'match', 'regex'));
    if (patterns.length === 0) return;

    const severity = String(pick(entry, 'severity') || 'medium').toLowerCase();
    const flags = String(pick(entry, 'flags') || 'gi');
    const compiled = [];

    for (const pattern of patterns) {
      try {
        compiled.push(pattern instanceof RegExp ? pattern : new RegExp(String(pattern), flags));
      } catch {
        /* skip invalid regex, never fail the scan */
      }
    }
    if (compiled.length === 0) return;

    out.push({
      id: String(pick(entry, 'id') || `SG-POLICY-${String(index + 1).padStart(3, '0')}`),
      title: String(pick(entry, 'title', 'name', 'message') || 'Custom policy rule'),
      severity: SEVERITY_SET.has(severity) ? severity : 'medium',
      confidence: String(pick(entry, 'confidence') || 'medium'),
      category: 'policy',
      owasp: pick(entry, 'owasp') || null,
      description: String(pick(entry, 'description') || pick(entry, 'message') || 'Matched a project policy rule.'),
      remediation: String(pick(entry, 'remediation', 'fix') || 'Resolve the match or refine the rule.'),
      patterns: compiled,
      views: asArray(pick(entry, 'views', 'view')).length ? asArray(pick(entry, 'views', 'view')) : undefined,
      policy: true,
    });
  });

  return out;
}

/** Sort helper used by reporters that show the worst rule first. */
export function bySeverity(a, b) {
  return compareSeverity(a.severity, b.severity);
}
