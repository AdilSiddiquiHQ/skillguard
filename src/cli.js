/**
 * Command line interface. Hand-rolled argument parsing, zero dependencies.
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import { exampleConfig, loadConfig } from './config.js';
import { evaluateGate, scan } from './scan.js';
import { renderTerminal } from './reporters/terminal.js';
import { renderSarif } from './reporters/sarif.js';
import { renderMarkdown } from './reporters/markdown.js';
import { renderBadge } from './reporters/badge.js';
import { ruleCount } from './rules/index.js';
import { pluralize } from './util.js';
import { TOOL_NAME, VERSION } from './version.js';

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

  paths                Files or directories to scan (default: .)
                       A skill is a folder containing SKILL.md

OPTIONS
  -h, --help           Show this help
  -v, --version        Show the version
      --all            Treat every Markdown file as a skill document
      --json           Print the full JSON report to stdout
      --sarif [file]   Write a SARIF report (default: skillguard.sarif)
      --markdown [f]   Write a Markdown report (default: skillguard-report.md)
      --badge [file]   Write an SVG badge (default: skillguard-badge.svg)
      --fail-on <sev>  Fail on critical|high|medium|low|none (default: high)
      --min-score <n>  Also fail when a skill scores >= n (0-100)
      --ignore <ids>   Comma-separated rule ids to skip (repeatable)
      --exclude <glob> Glob to skip (repeatable)
      --config <file>  Path to a .skillguard config file
      --init           Write an example .skillguard.yml
      --force          Overwrite when using --init
      --verbose        Show descriptions and fixes for every finding
      --quiet          Only print the final verdict line
      --no-color       Disable ANSI colour

EXIT CODES
  0  clean (no finding matched --fail-on)
  1  findings matched --fail-on, or --min-score was reached
  2  usage error
  3  internal error

EXAMPLES
  skillguard .                              scan the current project
  skillguard skills --fail-on critical      only critical findings fail CI
  skillguard . --sarif results.sarif        emit SARIF for GitHub code scanning
  skillguard . --badge docs/badge.svg       generate a README badge
  npx github:AdilSiddiquiHQ/skillguard .    run without installing
`;

const SEVERITY_VALUES = ['critical', 'high', 'medium', 'low', 'none'];

function parseArgs(argv) {
  const flags = {
    paths: [],
    json: false,
    sarif: null,
    markdown: null,
    badge: null,
    failOn: null,
    minScore: null,
    ignore: [],
    exclude: [],
    config: null,
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

  const takesOptionalValue = new Set(['--sarif', '--markdown', '--badge']);
  const takesValue = new Set(['--fail-on', '--min-score', '--ignore', '--exclude', '--config']);

  for (let i = 0; i < argv.length; i += 1) {
    let arg = argv[i];

    if (arg === '--help' || arg === '-h') flags.help = true;
    else if (arg === '--version' || arg === '-v') flags.version = true;
    else if (arg === '--json') flags.json = true;
    else if (arg === '--all') flags.all = true;
    else if (arg === '--init') flags.init = true;
    else if (arg === '--force') flags.force = true;
    else if (arg === '--verbose') flags.verbose = true;
    else if (arg === '--quiet') flags.quiet = true;
    else if (arg === '--no-color') flags.noColor = true;
    else if (arg === '--') {
      flags.paths.push(...argv.slice(i + 1));
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
    default:
      break;
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
  const gate = evaluateGate(report, effectiveConfig);

  if (flags.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else if (flags.quiet) {
    const s = report.summary;
    const verdict = s.failed > 0 ? 'FAIL' : s.review > 0 ? 'REVIEW' : 'PASS';
    process.stdout.write(
      `skillguard: ${verdict} — ${pluralize(s.skills, 'skill')}, ${pluralize(s.findings, 'finding')}\n`
    );
  } else {
    const color = !flags.noColor && !process.env.NO_COLOR && Boolean(process.stdout.isTTY);
    process.stdout.write(renderTerminal(report, { color, verbose: flags.verbose }));
    if (configPath) {
      process.stdout.write(`  config: ${configPath}\n\n`);
    }
  }

  const written = [];
  if (flags.sarif) {
    writeReportFile(cwd, flags.sarif, JSON.stringify(renderSarif(report), null, 2));
    written.push(flags.sarif);
  }
  if (flags.markdown) {
    writeReportFile(cwd, flags.markdown, renderMarkdown(report));
    written.push(flags.markdown);
  }
  if (flags.badge) {
    writeReportFile(cwd, flags.badge, renderBadge(report));
    written.push(flags.badge);
  }
  if (written.length > 0 && !flags.json && !flags.quiet) {
    process.stdout.write(`  wrote ${written.join(', ')}\n\n`);
  }

  return gate.failed ? 1 : 0;
}

export { parseArgs, HELP };
