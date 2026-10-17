# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-18

### Added

- Initial release: the `skillguard` CLI, zero runtime dependencies.
- 48 detection rules across 9 categories (injection, credentials, exfiltration,
  execution, supply chain, obfuscation, metadata, secrets, assets), mapped to
  the OWASP Agentic Skills Top 10.
- Deterministic risk scoring (0-100) with PASS / REVIEW / FAIL verdicts.
- Reporters for the terminal, JSON, SARIF 2.1.0, Markdown and SVG badges.
- Skill discovery for the open Agent Skills standard (folders with `SKILL.md`),
  including bundled script and binary asset inspection.
- `.skillguard.yml` configuration with `fail-on`, `min-score`, `ignore`,
  `exclude`, `allow` and configurable thresholds.
- Secret redaction in all output.
- A per-skill SBOM with SHA-256 hashes of every file.
- GitHub composite Action and a pre-commit hook definition.
- A test suite covering detection, scoring, reporters, config and the CLI.
- A generated rule reference in `docs/RULES.md`.

[Unreleased]: https://github.com/AdilSiddiquiHQ/skillguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AdilSiddiquiHQ/skillguard/releases/tag/v0.1.0
