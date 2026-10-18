/**
 * The complete SkillSleuth rule catalog.
 * Each rule maps to a category, a severity and an OWASP Agentic Skills
 * Top 10 identifier where applicable.
 */

import { injectionRules } from './injection.js';
import { credentialRules } from './credentials.js';
import { exfiltrationRules } from './exfiltration.js';
import { executionRules } from './execution.js';
import { supplyChainRules } from './supplychain.js';
import { obfuscationRules } from './obfuscation.js';
import { scopeRules } from './scope.js';
import { secretRules } from './secrets.js';
import { assetRules } from './assets.js';
import { evasionRules } from './evasion.js';
import { artifactRules } from './artifacts.js';
import { mcpRules } from './mcp.js';
import { pluginRules } from './plugin.js';

export const ALL_RULES = [
  ...injectionRules,
  ...credentialRules,
  ...exfiltrationRules,
  ...executionRules,
  ...supplyChainRules,
  ...obfuscationRules,
  ...evasionRules,
  ...artifactRules,
  ...mcpRules,
  ...pluginRules,
  ...scopeRules,
  ...secretRules,
  ...assetRules,
];

export const RULES_BY_ID = new Map(ALL_RULES.map((rule) => [rule.id, rule]));

export const CATEGORIES = [
  'injection',
  'credentials',
  'exfiltration',
  'execution',
  'supply-chain',
  'obfuscation',
  'evasion',
  'artifacts',
  'mcp',
  'plugin',
  'metadata',
  'secrets',
  'assets',
];

export function ruleCount() {
  return ALL_RULES.length;
}

export {
  injectionRules,
  credentialRules,
  exfiltrationRules,
  executionRules,
  supplyChainRules,
  obfuscationRules,
  scopeRules,
  secretRules,
  assetRules,
  evasionRules,
  artifactRules,
  mcpRules,
  pluginRules,
};
