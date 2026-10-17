/**
 * Configuration loading. Looks for .skillguard.yml / .skillguard.yaml /
 * .skillguard.json upward from the scan root, plus any --config override.
 */

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { parseSimpleYaml } from './frontmatter.js';
import { DEFAULT_THRESHOLDS } from './score.js';

const CONFIG_NAMES = ['.skillguard.yml', '.skillguard.yaml', '.skillguard.json'];

export const DEFAULT_CONFIG = {
  failOn: 'high',
  minScore: null,
  ignore: [],
  allow: [],
  exclude: [],
  scanAssets: true,
  thresholds: { ...DEFAULT_THRESHOLDS },
  maxFindingsPerRulePerFile: 5,
};

function normalize(raw) {
  const config = {
    ...DEFAULT_CONFIG,
    thresholds: { ...DEFAULT_THRESHOLDS },
  };

  if (!raw || typeof raw !== 'object') return config;

  if (typeof raw['fail-on'] === 'string') config.failOn = raw['fail-on'];
  if (typeof raw.failOn === 'string') config.failOn = raw.failOn;

  if (typeof raw['min-score'] === 'number') config.minScore = raw['min-score'];
  if (typeof raw.minScore === 'number') config.minScore = raw.minScore;

  for (const key of ['ignore', 'allow', 'exclude']) {
    const value = raw[key];
    if (Array.isArray(value)) config[key] = value.map(String);
    else if (typeof value === 'string' && value) config[key] = [value];
  }

  if (raw['scan-assets'] === false || raw.scanAssets === false) config.scanAssets = false;
  if (typeof raw['max-findings-per-rule-per-file'] === 'number') {
    config.maxFindingsPerRulePerFile = raw['max-findings-per-rule-per-file'];
  }

  const thresholds = raw.thresholds || raw;
  if (thresholds && typeof thresholds === 'object') {
    if (typeof thresholds.review === 'number') config.thresholds.review = thresholds.review;
    if (typeof thresholds.fail === 'number') config.thresholds.fail = thresholds.fail;
  }

  return config;
}

export function findConfigFile(startDir) {
  let dir = resolve(startDir);
  for (let depth = 0; depth < 12; depth += 1) {
    for (const name of CONFIG_NAMES) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export function loadConfig({ cwd = process.cwd(), configPath = null } = {}) {
  const path = configPath ? resolve(cwd, configPath) : findConfigFile(cwd);
  if (!path || !existsSync(path)) {
    return { config: { ...DEFAULT_CONFIG, thresholds: { ...DEFAULT_THRESHOLDS } }, path: null };
  }

  const text = readFileSync(path, 'utf8');
  let raw;
  try {
    raw = path.endsWith('.json') ? JSON.parse(text) : parseSimpleYaml(text);
  } catch (err) {
    throw new Error(`Failed to parse config at ${path}: ${err.message}`);
  }

  return { config: normalize(raw), path };
}

export function exampleConfig() {
  return `# SkillGuard configuration
# Docs: https://github.com/AdilSiddiquiHQ/skillguard#configuration

# Fail the run when a finding of this severity (or worse) is present.
# One of: critical | high | medium | low | none
fail-on: high

# Alternatively, fail when any skill scores at or above this value (0-100).
# min-score: 30

# Ignore specific rules by id.
ignore:
  - SG-EXEC-008

# Skip paths (glob, matches directories and their contents).
exclude:
  - vendor/**
  - test/fixtures/**

# Treat matching paths as intentionally risky (still reported, never fails).
allow:
  - examples/**

# Scores at or above these values produce REVIEW / FAIL verdicts.
thresholds:
  review: 30
  fail: 70
`;
}
