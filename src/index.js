/**
 * SkillGuard programmatic API.
 *
 *   import { scan, renderSarif } from 'skillguard';
 *
 *   const report = scan(['./skills'], { config });
 *   console.log(report.summary, report.skills[0].evasions);
 */

export { scan, scanSkill, evaluateGate, buildViews, buildArchiveViews } from './scan.js';
export { discoverSkills, classifySpecial } from './discover.js';
export { loadConfig, DEFAULT_CONFIG, exampleConfig, findConfigFile } from './config.js';
export { scoreFindings, verdictFor, summarize, DEFAULT_THRESHOLDS } from './score.js';
export { parseFrontmatter, parseSimpleYaml } from './frontmatter.js';
export { ALL_RULES, RULES_BY_ID, CATEGORIES, ruleCount } from './rules/index.js';
export { compilePolicyRules } from './policy.js';
export { fingerprint, computeBaseline, loadBaseline, applyBaseline } from './baseline.js';
export {
  buildStatement,
  canonicalize,
  generateKeyPair,
  signStatement,
  verifyEnvelope,
  fingerprintPublicKey,
} from './sign.js';
export {
  deobfuscate,
  extractEncodedPayloads,
  detectPadding,
  findConfusables,
} from './normalize.js';
export { extractArchive, extractStrings, readZip, isArchivePath, isBinaryArtifactPath } from './archive.js';
export { renderTerminal } from './reporters/terminal.js';
export { renderSarif } from './reporters/sarif.js';
export { renderMarkdown } from './reporters/markdown.js';
export { renderBadge } from './reporters/badge.js';
export { renderHtml } from './reporters/html.js';
export { renderGithub } from './reporters/github.js';
export { renderCycloneDx } from './reporters/cyclonedx.js';
export { TOOL_NAME, VERSION } from './version.js';
