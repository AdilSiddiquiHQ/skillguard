/**
 * Command line interface. Hand-rolled argument parsing, zero dependencies.
 *
 * Commands
 *   (default)      scan targets and report
 *   rules          list every rule in the catalog
 *   explain <id>   explain one rule in detail
 *   keygen         create an Ed25519 signing key pair
 *   sign <path>    scan a target and emit a signed attestation
 *   verify <file>  verify a signed attestation
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { exampleConfig, loadConfig } from './config.js';
import { evaluateGate, scan } from './scan.js';
import { renderTerminal } from './reporters/terminal.js';
import { renderSarif } from './reporters/sarif.js';
import { renderMarkdown } from './reporters/markdown.js';
import { renderBadge } from './reporters/badge.js';
import { renderHtml } from './reporters/html.js';
import { renderGithub } from './reporters/github.js';
import { renderCycloneDx } from './reporters/cyclonedx.js';
import { ALL_RULES, CATEGORIES, RULES_BY_ID, ruleCount } from './rules/index.js';
import { applyBaseline, computeBaseline, loadBaseline } from './baseline.js';
import { buildStatement, fingerprintPublicKey, generateKeyPair, signStatement, verifyEnvelope } from './sign.js';
import { pluralize } from './util.js';
import { TOOL_NAME, VERSION } from './version.js';

const DEFAULT_BASELINE = '.skillguard-baseline.json';
const DEFAULT_ATTESTATION = 'skillguard.attestation.json';

function writeReportFile(cwd, relativePath, content) {
  const target = resolve(cwd, relativePath);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content, 'utf8');
  return target;
}

const HELP = `${TOOL_NAME} ${VERSION} — scan AI agent skills for prompt injection,
credential theft and supply-chain attacks.

USAGE
  skillguard [paths...] [options]
  skillguard <command> [args]

  paths                Files or directories to scan (default: .)
                       A skill is a folder containing SKILL.md. Plugin
                       manifests, MCP configs and agent files are found too.

SCAN OPTIONS
  -h, --help           Show this help
  -v, --version        Show the version
      --all            Treat every Markdown file as a skill document
      --json           Print the full JSON report to stdout
      --sarif [file]   Write a SARIF report (default: skillguard.sarif)
      --markdown [f]   Write a Markdown report (default: skillguard-report.md)
      --badge [file]   Write an SVG badge (default: skillguard-badge.svg)
      --html [file]    Write a self-contained HTML report
      --sbom [file]    Write a CycloneDX 1.6 SBOM (default: skillguard.sbom.json)
      --github         Emit GitHub Actions annotations
      --fail-on <sev>  Fail on critical|high|medium|low|none (default: high)
      --min-score <n>  Also fail when a skill scores >= n (0-100)
      --baseline <f>   Ignore findings present in this baseline file
      --write-baseline [f]
                       Record current findings as the baseline, then exit
      --ignore <ids>   Comma-separated rule ids to skip (repeatable)
      --exclude <glob> Glob to skip (repeatable)
      --config <file>  Path to a .skillguard config file
      --init           Write an example .skillguard.yml
      --force          Overwrite when using --init or --write-baseline
      --verbose        Show descriptions and fixes for every finding
      --quiet          Only print the final verdict line
      --no-color       Disable ANSI colour

COMMANDS
  rules [--json]           List every rule in the catalog
  explain <rule-id>        Explain a single rule
  keygen [--out <dir>]     Create an Ed25519 signing key pair
  sign <path> --key <f>    Scan and emit a signed attestation
  verify <file> --key <f>  Verify a signed attestation

EXIT CODES
  0  clean (no finding matched --fail-on)
  1  findings matched --fail-on, or --min-score was reached
  2  usage error
  3  internal error

EXAMPLES
  skillguard .                              scan the current project
  skillguard skills --fail-on critical      only critical findings fail CI
  skillguard . --sarif results.sarif        emit SARIF for GitHub code scanning
  skillguard . --github                     annotate a pull request inline
  skillguard . --html report.html           write a shareable HTML report
  skillguard . --sbom sbom.json             emit a CycloneDX SBOM
  skillguard . --write-baseline             adopt on an existing repo
  skillguard explain SG-EVA-001             learn about one rule
  npx github:AdilSiddiquiHQ/skillguard .    run without installing
`;

const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low', 'none'];
const COMMANDS = new Set(['rules', 'explain', 'keygen', 'sign', 'verify']);

function parseArgs(argv) {
  const flags = {
    command: null,
    commandArgs: [],
    paths: [],
    json: false,
    sarif: null,
    markdown: null,
    badge: null,
    html: null,
    sbom: null,
    github: false,
    failOn: null,
    minScore: null,
    ignore: [],
    exclude: [],
    config: null,
    baseline: null,
    writeBaseline: null,
    key: null,
    out: null,
    all: false,
    init: false,
    force: false,
    verbose: false,
    quiet: false,
    noColor: false,
    help: false,
    version: false,
    error: null,
  };

  const takesOptionalValue = new Set(['--sarif', '--markdown', '--badge', '--html', '--sbom', '--write-baseline']);
  const takesValue = new Set(['--fail-on', '--min-score', '--ignore', '--exclude', '--config', '--baseline', '--key', '--out']);

  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i];

    if (COMMANDS.has(arg) && flags.command === null) {
      flags.command = arg;
      continue;
    }

    if (arg === '--help' || arg === '-h') flags.help = true;
    else if (arg === '--version' || arg === '-v') flags.version = true;
    else if (arg === '--json') flags.json = true;
    else if (arg === '--all') flags.all = true;
    else if (arg === '--init') flags.init = true;
    else if (arg === '--force') flags.force = true;
    else if (arg === '--verbose') flags.verbose = true;
    else if (arg === '--quiet') flags.quiet = true;
    else if (arg === '--no-color') flags.noColor = true;
    else if (arg === '--github') flags.github = true;
    else if (arg === '--') {
      const rest = argv.slice(i + 1);
      if (flags.command) flags.commandArgs.push(...rest);
      else flags.paths.push(...rest);
      break;
    } else if (arg.startsWith('--')) {
      let value = null;
      const eq = arg.indexOf('=');
      if (eq !== -1) {
        value = arg.slice(eq + 1);
        arg = arg.slice(0, eq);
      }

      if (takesValue.has(arg)) {
        if (value === null) {
          value = argv[i + 1];
          if (value === undefined || value.startsWith('-')) {
            flags.error = `Option ${arg} requires a value`;
            return flags;
          }
          i += 1;
        }
        applyValueFlag(flags, arg, value);
      } else if (takesOptionalValue.has(arg)) {
        if (value === null && argv[i + 1] !== undefined && !argv[i + 1].startsWith('-')) {
          value = argv[i + 1];
          i += 1;
        }
        applyValueFlag(flags, arg, value);
      } else {
        flags.error = `Unknown option: ${arg}`;
        return flags;
      }
    } else if (arg.startsWith('-') && arg.length > 1) {
      flags.error = `Unknown option: ${arg}`;
      return flags;
    } else if (flags.command) {
      flags.commandArgs.push(arg);
    } else {
      flags.paths.push(arg);
    }
  }

  return flags;
}

function applyValueFlag(flags, name, value) {
  switch (name) {
    case '--sarif':
      flags.sarif = value || 'skillguard.sarif';
      break;
    case '--markdown':
      flags.markdown = value || 'skillguard-report.md';
      break;
    case '--badge':
      flags.badge = value || 'skillguard-badge.svg';
      break;
    case '--html':
      flags.html = value || 'skillguard-report.html';
      break;
    case '--sbom':
      flags.sbom = value || 'skillguard.sbom.json';
      break;
    case '--write-baseline':
      flags.writeBaseline = value || DEFAULT_BASELINE;
      break;
    case '--fail-on':
      if (!SEVERITY_VALUES.includes(value)) {
        flags.error = `Invalid --fail-on value: ${value} (expected ${SEVERITY_VALUES.join('|')})`;
        break;
      }
      flags.failOn = value;
      break;
    case '--min-score': {
      const n = Number(value);
      if (!Number.isFinite(n) || n < 0 || n > 100) {
        flags.error = `Invalid --min-score value: ${value} (expected 0-100)`;
        break;
      }
      flags.minScore = n;
      break;
    }
    case '--ignore':
      flags.ignore.push(...value.split(',').map((s) => s.trim()).filter(Boolean));
      break;
    case '--exclude':
      flags.exclude.push(value);
      break;
    case '--config':
      flags.config = value;
      break;
    case '--baseline':
      flags.baseline = value;
      break;
    case '--key':
      flags.key = value;
      break;
    case '--out':
      flags.out = value;
      break;
    default:
      break;
  }
}

function printRules(flags) {
  if (flags.json) {
    const payload = ALL_RULES.map((r) => serializeRule(r));
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    return 0;
  }

  const lines = ['', `  ${TOOL_NAME} rule catalog · ${ruleCount()} rules`, ''];
  for (const category of CATEGORIES) {
    const rules = ALL_RULES.filter((r) => r.category === category);
    if (rules.length === 0) continue;
    lines.push(`  ${category.toUpperCase()}`);
    for (const rule of rules) {
      lines.push(`    ${rule.id.padEnd(14)} ${String(rule.severity).padEnd(9)} ${rule.title}`);
    }
    lines.push('');
  }
  process.stdout.write(`${lines.join('\n')}\n`);
  return 0;
}

function serializeRule(rule) {
  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    confidence: rule.confidence || 'medium',
    category: rule.category,
    owasp: rule.owasp || null,
    description: rule.description,
    remediation: rule.remediation || '',
    perSkill: Boolean(rule.perSkill),
    views: rule.views || null,
  };
}

function explainRule(id) {
  const rule = RULES_BY_ID.get(id) || ALL_RULES.find((r) => r.id.toLowerCase() === String(id).toLowerCase());
  if (!rule) {
    process.stderr.write(`${TOOL_NAME}: unknown rule "${id}". Run \`skillguard rules\` to list them.\n`);
    return 2;
  }
  const lines = [
    '',
    `  ${rule.id}  ${rule.title}`,
    '',
    `  severity     ${rule.severity}`,
    `  confidence   ${rule.confidence || 'medium'}`,
    `  category     ${rule.category}`,
    `  owasp        ${rule.owasp || '—'}`,
    '',
    '  why it matters',
    `    ${rule.description}`,
    '',
    '  how to fix it',
    `    ${rule.remediation || 'Remove the behaviour described above.'}`,
    '',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
  return 0;
}

function keygen(flags, cwd) {
  const dir = flags.out ? resolve(cwd, flags.out) : cwd;
  mkdirSync(dir, { recursive: true });
  const privatePath = resolve(dir, 'skillguard.key');
  const publicPath = resolve(dir, 'skillguard.pub');

  if (!flags.force && (existsSync(privatePath) || existsSync(publicPath))) {
    process.stderr.write(`${TOOL_NAME}: key files already exist in ${dir} (use --force to overwrite)\n`);
    return 2;
  }

  const { privateKey, publicKey } = generateKeyPair();
  writeFileSync(privatePath, privateKey, { encoding: 'utf8', mode: 0o600 });
  writeFileSync(publicPath, publicKey, 'utf8');
  try {
    chmodSync(privatePath, 0o600);
  } catch {
    /* best effort on platforms without POSIX modes */
  }

  process.stdout.write(
    `\n  wrote ${privatePath} (keep this secret)\n  wrote ${publicPath}\n\n  key id: ${fingerprintPublicKey(publicKey)}\n\n`
  );
  return 0;
}

function signTarget(flags, cwd) {
  if (!flags.key) {
    process.stderr.write(`${TOOL_NAME}: sign requires --key <private-key-file>\n`);
    return 2;
  }
  const keyPath = resolve(cwd, flags.key);
  if (!existsSync(keyPath)) {
    process.stderr.write(`${TOOL_NAME}: private key not found: ${keyPath}\n`);
    return 2;
  }

  const { config } = loadConfig({ cwd, configPath: flags.config });
  const paths = flags.paths.length ? flags.paths : ['.'];
  const report = scan(paths, { cwd, config, all: flags.all });

  let privateKey;
  try {
    privateKey = readFileSync(keyPath, 'utf8');
  } catch (err) {
    process.stderr.write(`${TOOL_NAME}: could not read key: ${err.message}\n`);
    return 3;
  }

  const statement = buildStatement(report);
  const envelope = signStatement(statement, privateKey);
  const out = flags.out || DEFAULT_ATTESTATION;
  const target = writeReportFile(cwd, out, `${JSON.stringify(envelope, null, 2)}\n`);

  process.stdout.write(
    `\n  signed attestation written to ${target}\n  subjects: ${statement.subject.length} file(s) · key id: ${envelope.signatures[0].keyid}\n\n`
  );
  return 0;
}

function verifyAttestation(flags, cwd) {
  const file = flags.paths[0] || flags.commandArgs[0];
  if (!file) {
    process.stderr.write(`${TOOL_NAME}: verify requires an attestation file\n`);
    return 2;
  }
  if (!flags.key) {
    process.stderr.write(`${TOOL_NAME}: verify requires --key <public-key-file>\n`);
    return 2;
  }

  let envelope;
  try {
    envelope = JSON.parse(readFileSync(resolve(cwd, file), 'utf8'));
  } catch (err) {
    process.stderr.write(`${TOOL_NAME}: could not read attestation: ${err.message}\n`);
    return 2;
  }

  let publicKey;
  try {
    publicKey = readFileSync(resolve(cwd, flags.key), 'utf8');
  } catch (err) {
    process.stderr.write(`${TOOL_NAME}: could not read public key: ${err.message}\n`);
    return 2;
  }

  const result = verifyEnvelope(envelope, publicKey);
  if (!result.valid) {
    process.stdout.write(`\n  ✖ INVALID — ${result.reason}\n\n`);
    return 1;
  }

  const statement = result.statement || {};
  const subjects = Array.isArray(statement.subject) ? statement.subject.length : 0;
  process.stdout.write(
    `\n  ✔ VALID signature\n  predicate: ${statement.predicateType || '—'}\n  subjects : ${subjects} file(s)\n\n`
  );
  return 0;
}

function runCommand(flags, cwd) {
  switch (flags.command) {
    case 'rules':
      return printRules(flags);
    case 'explain':
      return explainRule(flags.commandArgs[0]);
    case 'keygen':
      return keygen(flags, cwd);
    case 'sign':
      return signTarget(flags, cwd);
    case 'verify':
      return verifyAttestation(flags, cwd);
    default:
      return null;
  }
}

export async function main(argv) {
  const flags = parseArgs(argv);

  if (flags.help) {
    process.stdout.write(HELP);
    return 0;
  }

  if (flags.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  if (flags.error) {
    process.stderr.write(`${TOOL_NAME}: ${flags.error}\n\nRun \`skillguard --help\` for usage.\n`);
    return 2;
  }

  const cwd = process.cwd();

  if (flags.command) {
    const code = runCommand(flags, cwd);
    if (code !== null) return code;
  }

  if (flags.init) {
    const target = resolve(cwd, '.skillguard.yml');
    if (existsSync(target) && !flags.force) {
      process.stderr.write(`${TOOL_NAME}: ${target} already exists (use --force to overwrite)\n`);
      return 2;
    }
    writeFileSync(target, exampleConfig(), 'utf8');
    process.stdout.write(`Wrote ${target}\n`);
    return 0;
  }

  const { config, path: configPath } = loadConfig({ cwd, configPath: flags.config });

  const effectiveConfig = {
    ...config,
    exclude: [...config.exclude, ...flags.exclude],
    ignore: [...config.ignore, ...flags.ignore],
  };
  if (flags.failOn) effectiveConfig.failOn = flags.failOn;
  if (typeof flags.minScore === 'number') effectiveConfig.minScore = flags.minScore;

  const report = scan(flags.paths, { cwd, config: effectiveConfig, all: flags.all });

  if (flags.writeBaseline) {
    const target = resolve(cwd, flags.writeBaseline);
    if (existsSync(target) && !flags.force) {
      process.stderr.write(
        `${TOOL_NAME}: ${target} already exists (use --force to overwrite)\n`
      );
      return 2;
    }
    const baseline = computeBaseline(report, { root: cwd });
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
    process.stdout.write(
      `Wrote ${target} — ${baseline.count} finding(s) recorded and excluded from future runs.\n`
    );
    return 0;
  }

  const baselinePath = flags.baseline || effectiveConfig.baseline;
  let finalReport = report;
  if (baselinePath) {
    try {
      const baseline = loadBaseline(resolve(cwd, baselinePath));
      if (baseline) finalReport = applyBaseline(report, baseline, effectiveConfig.thresholds);
    } catch (err) {
      process.stderr.write(`${TOOL_NAME}: ${err.message}\n`);
      return 2;
    }
  }

  const gate = evaluateGate(finalReport, effectiveConfig);

  if (flags.json) {
    process.stdout.write(`${JSON.stringify(finalReport, null, 2)}\n`);
  } else if (flags.quiet) {
    const s = finalReport.summary;
    const verdict = gate.failed ? 'FAIL' : s.review > 0 ? 'REVIEW' : 'PASS';
    process.stdout.write(
      `skillguard: ${verdict} — ${pluralize(s.skills, 'target')}, ${pluralize(s.findings, 'finding')}\n`
    );
  } else {
    if (flags.github) {
      process.stdout.write(renderGithub(finalReport, { failOn: effectiveConfig.failOn }));
    }
    const color = !flags.noColor && !process.env.NO_COLOR && Boolean(process.stdout.isTTY);
    process.stdout.write(renderTerminal(finalReport, { color, verbose: flags.verbose, gateFailed: gate.failed }));
    if (configPath) {
      process.stdout.write(`  config: ${configPath}\n\n`);
    }
    if (baselinePath && finalReport.baseline) {
      process.stdout.write(`  baseline: ${baselinePath}\n\n`);
    }
  }

  const written = [];
  if (flags.sarif) {
    writeReportFile(cwd, flags.sarif, JSON.stringify(renderSarif(finalReport), null, 2));
    written.push(flags.sarif);
  }
  if (flags.markdown) {
    writeReportFile(cwd, flags.markdown, renderMarkdown(finalReport));
    written.push(flags.markdown);
  }
  if (flags.badge) {
    writeReportFile(cwd, flags.badge, renderBadge(finalReport));
    written.push(flags.badge);
  }
  if (flags.html) {
    writeReportFile(cwd, flags.html, renderHtml(finalReport));
    written.push(flags.html);
  }
  if (flags.sbom) {
    writeReportFile(cwd, flags.sbom, `${JSON.stringify(renderCycloneDx(finalReport), null, 2)}\n`);
    written.push(flags.sbom);
  }
  if (written.length > 0 && !flags.json && !flags.quiet) {
    process.stdout.write(`  wrote ${written.join(', ')}\n\n`);
  }

  return gate.failed ? 1 : 0;
}

export { parseArgs, HELP };
