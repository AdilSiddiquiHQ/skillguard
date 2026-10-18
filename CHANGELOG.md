# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-10-18

### Changed

- **Renamed from SkillGuard to SkillSleuth.** "SkillGuard" was already in use by
  another agent-skill scanner, which makes a two-word name in a crowded
  category worse than useless: searching for the project found someone else's.
  The rename touches the package name, the `skillsleuth` binary, the config
  filename (`.skillsleuth.yml`), generated file names (`skillsleuth.sarif`,
  `skillsleuth-badge.svg`, `skillsleuth.sbom.json`), baseline and attestation
  file names, and the `SKILLSLEUTH_*` environment variables. Nothing else about
  behaviour changed — the rules, scoring and reports are byte-identical apart
  from the name. Historical tags `v0.1.0`–`v0.3.1` still contain the old name,
  as they should.
- The attestation predicate type was `https://skillguard.dev/...`, a domain that
  does not exist. It is now a resolvable URL under the repository, so a signed
  statement points somewhere real.

## [0.3.1] - 2026-10-18

### Fixed

- **Defensive-text suppression could hide real findings.** The check that skips
  text *about* an attack — a blocklist quoting `git reset --hard`, a guide
  saying "never run `curl | sh`" — matched any of ~35 keywords within a 400
  character window. An unrelated sentence far away, such as a fixture's own
  "Do not copy this file" comment, therefore silenced a genuine private-key
  read. Suppression is now scoped to the match's own clause (for a negation)
  or its paragraph and heading (for a guardrail marker). The change restored
  the private-key, instruction-override and approval-bypass findings on the
  bundled malicious fixture while leaving real-world precision unchanged.
- The README's sample output is now checked by a test, so a sample the tool no
  longer prints cannot ship again.

## [0.3.0] - 2026-10-18

Precision. A security scanner that cries wolf gets uninstalled, so this release
is measured rather than asserted.

### Changed

- Rewrote the noisy rules to require context instead of a keyword: a
  concealment adverb must be attached to an action (`silently exfiltrate`, not
  `the SDK silently retries`), a secret path must directly follow a read
  command, `curl | sh` must be command syntax, `sudo` must start a command and
  `rm -rf` must target root, home or a wildcard.
- Text that describes or warns about an attack is skipped, so a blocklist of
  `git reset --hard` is not itself reported.
- Severity is now tiered by context for `SG-EXEC-004`, `SG-EXFIL-001` and
  `SG-INJ-004`.
- Fixed `SG-META-007` to parse comma-separated `allowed-tools`, and to treat a
  granted shell as covering shell, network and file-write capabilities.

### Added

- A labelled precision corpus (`test/corpus/clean`, `test/corpus/malicious`) and
  `test/precision.test.js`, run in CI: a clean skill must produce no critical or
  high finding, and every labelled attack must still be caught.
- `scripts/measure-precision.js` (`npm run precision`) to reproduce the
  measurement against public skill repositories.

On 66 skills from three public collections (`anthropics/skills`,
`mattpocock/skills`, `vercel-labs/skills`) findings fell from roughly 400 —
about 100 of them critical — to 10, with zero critical or high.

## [0.2.0] - 2026-10-18

Evasion resistance, broader coverage and provenance. This release is a direct
response to the June 2026 Trail of Bits research that bypassed every shipping
agent-skill scanner.

### Added

- **Multi-view scanning engine.** Every text file is examined raw, deobfuscated,
  decoded (base64 / hex / percent, one layer deep) and unpacked (zip / docx /
  xlsx / pptx / jar, including nested archives). Findings keep truthful line and
  column numbers via an index map back to the original file.
- **4 evasion rules** (`SG-EVA-*`): context-flood padding, homoglyph
  substitution, and payloads recovered from encodings or embedded content.
  Findings carry an `evasion` field naming the trick.
- **4 artifact rules** (`SG-ART-*`): compiled bytecode with no matching source
  (the poisoned-`.pyc` attack), dangerous strings inside binaries, script
  payloads inside documents, and opaque file types.
- **7 MCP rules** (`SG-MCP-*`): shell-piped servers, unpinned servers, hardcoded
  secrets, permission-bypass flags, plaintext HTTP, home-rooted filesystems and
  blanket auto-approval.
- **3 plugin rules** (`SG-PLUG-*`): lifecycle hooks that run shell commands or
  download remote code, and matcher-less hooks.
- **5 more supply-chain rules**: registry/index rewrites (`.npmrc`, `pip.conf`,
  `GOPRIVATE`/`GOPROXY`), `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` injection,
  runtime compilation, TLS-verification disabling and global installs.
- **3 more metadata rules**: undeclared capabilities, instruction-like
  frontmatter and out-of-spec fields.
- **Multi-format discovery**: plugin manifests, MCP configs and agent
  instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
  `.cursor/rules/*.mdc`), in addition to `SKILL.md` skills. Hidden files are
  scanned deliberately.
- **Baseline mode** (`--baseline`, `--write-baseline`) to adopt the scanner on
  an existing repository and fail only on new findings.
- **Provenance and integrity**: `keygen`, `sign` and `verify` produce and check
  in-toto style statements in a DSSE envelope, signed with Ed25519.
- **CycloneDX 1.6 SBOM output** (`--sbom`), with per-file SHA-256 hashes and
  findings emitted as `vulnerabilities`.
- **Self-contained HTML report** (`--html`).
- **GitHub Actions annotations** (`--github`).
- **Policy as code**: declarative custom rules and `severity-overrides` in
  `.skillsleuth.yml`.
- **New commands**: `rules`, `explain <rule-id>`.
- Adversarial fixtures under `examples/evasion/` and the `test/evasion.test.js`
  regression suite, wired into CI.
- `docs/EVASION.md` and `docs/ARCHITECTURE.md`.

### Changed

- Rule count: **48 → 75**, categories **9 → 13**.
- `--fail-on none` is now honoured consistently across the terminal report and
  the process exit code.
- The summary now counts only active findings; baselined findings stay visible
  but are excluded from scoring and the gate.

## [0.1.0] - 2026-10-18

### Added

- Initial release: the `skillsleuth` CLI, zero runtime dependencies.
- 48 detection rules across 9 categories (injection, credentials, exfiltration,
  execution, supply chain, obfuscation, metadata, secrets, assets), mapped to
  the OWASP Agentic Skills Top 10.
- Deterministic risk scoring (0-100) with PASS / REVIEW / FAIL verdicts.
- Reporters for the terminal, JSON, SARIF 2.1.0, Markdown and SVG badges.
- Skill discovery for the open Agent Skills standard (folders with `SKILL.md`),
  including bundled script and binary asset inspection.
- `.skillsleuth.yml` configuration with `fail-on`, `min-score`, `ignore`,
  `exclude`, `allow` and configurable thresholds.
- Secret redaction in all output.
- A per-skill SBOM with SHA-256 hashes of every file.
- GitHub composite Action and a pre-commit hook definition.
- A test suite covering detection, scoring, reporters, config and the CLI.
- A generated rule reference in `docs/RULES.md`.

[Unreleased]: https://github.com/AdilSiddiquiHQ/skillsleuth/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/AdilSiddiquiHQ/skillsleuth/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/AdilSiddiquiHQ/skillsleuth/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/AdilSiddiquiHQ/skillsleuth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/AdilSiddiquiHQ/skillsleuth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/AdilSiddiquiHQ/skillsleuth/releases/tag/v0.1.0
