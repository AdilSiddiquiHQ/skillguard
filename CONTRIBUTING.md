# Contributing to SkillSleuth

Thanks for helping make the agent skills ecosystem safer to use.

## Getting started

```bash
git clone https://github.com/AdilSiddiquiHQ/skillsleuth
cd skillsleuth
node --test          # the full suite, no dependencies to install
node bin/skillsleuth.js examples/cleanup-trap
```

There is no build step and no `npm install` required. Node 18 or newer.

## Project layout

```
bin/skillsleuth.js        CLI entry point
src/cli.js               argument parsing and output
src/discover.js          finds skills (folders containing SKILL.md)
src/scan.js              runs rules, dedupes, scores
src/score.js             scoring and verdict thresholds
src/config.js            .skillsleuth.yml loading
src/frontmatter.js       minimal YAML frontmatter parser
src/rules/*.js           the rule catalog, one file per category
src/reporters/*.js       terminal, SARIF, Markdown and badge output
test/*.test.js           node:test suites
scripts/                 documentation generator
docs/RULES.md            generated — do not edit by hand
```

## Adding a rule

This is the most valuable contribution and a great first issue. A rule is a
plain object with either regex `patterns` or a `check(ctx)` function:

```js
{
  id: 'SG-EXEC-009',
  title: 'Short description of the pattern',
  severity: 'high',            // critical | high | medium | low | info
  confidence: 'medium',        // high | medium | low
  category: 'execution',       // one of the categories in rules/index.js
  owasp: 'AST05',              // optional
  description: 'What it detects and why it matters.',
  remediation: 'What the user should do instead.',
  patterns: [/\bsome-command\b/gi],
}
```

Rules that need more than a regex can export `check(ctx)` and return findings
via `findingAt(this, ctx, index, matchedText)`.

Requirements for a rule PR:

1. A unique `SG-<CATEGORY>-<NNN>` id.
2. At least one test in `test/scan.test.js` that proves a real detection.
3. A realistic example. Push the pattern toward true positives; justify the
   false-positive trade-off in the PR description.
4. Run `node scripts/generate-rules-doc.js` so the docs stay in sync.

Keep severities honest. A rule that fires on ordinary, safe behaviour should be
`low` or `info`, or it should not exist.

## Style

- Plain ES modules, no TypeScript build step, no runtime dependencies.
- 2-space indentation, single quotes, semicolons.
- Prefer clear names over comments; comment the *why*.

## Tests

- Add a test for any behaviour change.
- `node --test` must pass on Node 18, 20, 22 and 24.
- Determinism matters: scanning the same input twice must produce identical
  findings in the same order.

## Commits and pull requests

- Conventional Commits are appreciated (`feat(rules): detect X`).
- One logical change per PR.
- Describe the false-positive risk of a new rule explicitly.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
