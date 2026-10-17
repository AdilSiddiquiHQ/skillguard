# Architecture

SkillGuard is plain ESM JavaScript with no build step and no runtime
dependencies. Everything is auditable in place.

## Data flow

```
argv ─▶ cli.js
          │  parse flags, load config, apply severity overrides
          ▼
        scan.js ── discover.js ──▶ targets (skill | plugin | mcp | agents)
          │
          ├─ buildViews(file)         raw · deobfuscated · decoded
          ├─ buildArchiveViews(file)  zip/docx/xlsx/pptx/jar entries
          ├─ prepareFiles(skill)      parsed JSON · binary strings
          │
          ├─ rules (ALL_RULES + policy rules)
          │     patterns ─ runPatterns()
          │     check(ctx) ─ custom logic
          │
          ├─ dedupe ─ apply severity overrides ─ sort
          ├─ score.js ─ scoreFindings · verdictFor
          ▼
        report { summary, skills[], sbom }
          │
          ├─ baseline.js ─ applyBaseline (optional)
          ├─ scan.js#evaluateGate ─ exit code
          ▼
        reporters ─ terminal · json · sarif · markdown · html · github · cyclonedx · badge
```

## Modules

| Module | Responsibility |
|---|---|
| `src/cli.js` | Argument parsing, commands (`rules`, `explain`, `keygen`, `sign`, `verify`), output orchestration, exit codes. |
| `src/discover.js` | Target discovery: skills, plugin manifests, MCP configs, agent files. File loading, hashing, binary detection. |
| `src/scan.js` | View construction, rule execution, dedupe, scoring, gate evaluation. |
| `src/normalize.js` | Deobfuscation (zero-width, homoglyphs, NFKC, escapes) and encoded-payload extraction. |
| `src/archive.js` | Minimal ZIP reader (central-directory driven, `node:zlib`), string extraction, artefact classification. |
| `src/policy.js` | Compiles declarative `rules:` from config into engine rules. |
| `src/baseline.js` | Line-independent fingerprints, baseline computation and application. |
| `src/sign.js` | Ed25519 key generation, in-toto statement construction, DSSE envelope signing and verification. |
| `src/score.js` | Deterministic scoring and PASS/REVIEW/FAIL verdicts. |
| `src/config.js` | Config discovery and normalisation. |
| `src/frontmatter.js` | A small YAML subset parser for `SKILL.md` frontmatter and config files. |
| `src/util.js` | Severity handling, hashing, entropy, glob matching, redaction. |
| `src/reporters/*` | One module per output format. |

## The rule object

A rule is plain data. No class hierarchy, no registration ceremony.

```js
{
  id: 'SG-EXEC-001',           // stable, referenced by ignore / severity-overrides / baselines
  title: 'Remote code executed through a pipe',
  severity: 'critical',        // critical | high | medium | low | info
  confidence: 'high',          // high | medium | low — multiplies the score
  category: 'execution',       // must be in CATEGORIES
  owasp: 'AST05',              // OWASP Agentic Skills Top 10 mapping (optional)
  description: '...',          // why it matters (shown by --verbose and explain)
  remediation: '...',          // how to fix it
  patterns: [/.../gi],         // OR a check function
  check(ctx) { return []; },   // optional custom logic
  views: ['raw'],              // optional: restrict to raw | deobfuscated | decoded | archive
  perSkill: false,             // optional: run once per skill with file metadata
  targets: 'skill',            // optional: only run on the SKILL.md file
}
```

### The `ctx` passed to `check`

| Field | Meaning |
|---|---|
| `text` | The current view's text. |
| `lineStarts` | Line-start offsets of the current view. |
| `posFor(index)` | Returns `{ line, column }` in the **original** file, following the view's index map. Use this, not `posAt`, so obfuscation does not distort positions. |
| `file` | The file record: `path`, `abs`, `sha256`, `bytes`, `binary`, plus `json` (parsed JSON) and `strings` (binary strings) when applicable. |
| `fileLabel` | The path to report — the file itself, or `file::entry` / `file (base64)`. |
| `view` | `{ kind, name }` for the current view. |
| `evasion` | The obfuscation that produced this view, if any. |
| `derivedFrom` | `{ file, line?, entry?, encoding? }` when the view is not line-aligned. |
| `frontmatter`, `frontmatterPresent`, `isSkillFile`, `skill`, `files`, `entryName` | Context. |

Always emit findings through `findingAt(rule, ctx, index, match, extra)` — it
applies redaction and copies the evasion/derived-from metadata.

## Adding a rule

1. Pick a category file in `src/rules/`, or add one and register it in
   `src/rules/index.js`.
2. Add the rule object. Prefer `patterns` when a regex will do; use `check` when
   you need file metadata (JSON, file lists) or multi-step logic.
3. If the rule only makes sense for recovered payloads, set
   `views: ['decoded', 'archive']`.
4. Add a test to `test/scan.test.js` or `test/evasion.test.js`.
5. Run `node scripts/generate-rules-doc.js` to refresh `docs/RULES.md`.
6. Run `node --test`.

## Adding a reporter

A reporter is a pure function `(report, options) => string | object` in
`src/reporters/`. Wire it into `src/cli.js` behind a flag (see `--html` or
`--sbom` for the pattern). Repositories rendering structured output should return
an object and let the CLI serialise it.

## Invariants

- **Deterministic.** No randomness except `crypto.randomUUID()` used purely as an
  SBOM serial number. Same input, same output.
- **Offline.** No module performs a network request.
- **Non-executing.** Scanned content is never evaluated, imported or spawned.
- **Bounded.** Archive depth, entry counts, decompressed size and per-rule match
  counts are all capped so a crafted target cannot exhaust memory or time.
- **Redacting.** Findings that may contain secrets are masked by `findingAt`.
