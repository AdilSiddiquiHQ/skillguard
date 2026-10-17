/**
 * SkillGuard programmatic API.
 *
 *   import { scan, renderSarif } from 'skillguard';
 *
 *   const report = scan(['./skills'], { config });
 *   console.log(report.summary);
 */

export { scan, scanSkill, evaluateGate } from './scan.js';
export { discoverSkills } from './discover.js';
export { loadConfig, DEFAULT_CONFIG, exampleConfig, findConfigFile } from './config.js';
export { scoreFindings, verdictFor, summarize, DEFAULT_THRESHOLDS } from './score.js';
export { parseFrontmatter, parseSimpleYaml } from './frontmatter.js';
export { ALL_RULES, RULES_BY_ID, CATEGORIES, ruleCount } from './rules/index.js';
export { renderTerminal } from './reporters/terminal.js';
export { renderSarif } from './reporters/sarif.js';
export { renderMarkdown } from './reporters/markdown.js';
export { renderBadge } from './reporters/badge.js';
export { TOOL_NAME, VERSION } from './version.js';
