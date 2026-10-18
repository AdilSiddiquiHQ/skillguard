# Evasion resistance

This document explains *why* SkillSleuth scans views instead of files, what it
catches today, and where the honest limits are. It is the technical companion to
the "evasion resistance" section of the README.

## The problem

In June 2026, Trail of Bits published
[The sorry state of skill distribution](https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/).
They bypassed ClawHub's malicious-skill detector, Cisco's agent-skill scanner and
all three scanners behind Vercel's `skills.sh` in under an hour each — three of
four on the first try. The techniques had nothing to do with the malware:

1. **Context flood.** Prepend 100,000 blank lines. If the scanner truncates the
   file before it reaches the payload, the payload is never seen.
2. **Archive indirection.** Ship a `.docx` (a ZIP of XML) containing an embedded
   shell script. The document scanner reads the XML, not the script.
3. **Compiled-artefact poisoning.** Ship a `.pyc` that differs from the `.py`
   beside it. The scanner reads the source; the interpreter runs the bytecode.
4. **Config rewriting.** Overwrite `.npmrc` so every later install resolves
   through an attacker-controlled registry, and leave the judgement to an LLM.
5. **Opaque files.** Anything hidden or binary was reported as
   "not prepared to evaluate" and skipped.

The lesson was not "static analysis is dead". It was that scanning a file as a
single byte string is not enough. An attacker gets unlimited attempts; the
matcher only has to miss once.

## The model

SkillSleuth does not scan a file. It scans a set of **views** derived from the
file, and every view keeps an index map back to the original bytes.

```
file ─┬─▶ raw            the bytes exactly as written
      ├─▶ deobfuscated   zero-width stripped · homoglyphs folded ·
      │                  NFKC normalised · \uXXXX, \xXX and &#xNN; decoded
      ├─▶ decoded:*      base64 / hex / percent payloads, decoded
      │                  (and decoded again, one layer deeper)
      ├─▶ archive:*      entries inside zip / docx / xlsx / pptx / jar
      │                  (nested archives included)
      └─▶ binary         printable strings extracted from compiled artefacts
```

Every rule runs against every applicable view. A rule can restrict itself with
`views: ['decoded', 'archive']` (used by the `SG-EVA-*` rules that reason about
recovered payloads), but by default a rule sees everything.

### Truthful positions

Obfuscation must not cost the reader the line number. Two mechanisms keep
positions honest:

- **Character-level transforms** (zero-width removal, homoglyph folding, NFKC,
  escape decoding) build a per-character map. `map[i]` is the index in the
  *original* text for output character `i`. When a rule matches at index `i`,
  the reported line and column are computed from the original line starts.
- **Derived views** (decoded payloads, archive entries, binary strings) are not
  line-aligned with the original, so they carry their own line numbers and a
  `derivedFrom` pointer instead:

  ```
  examples/evasion/encoded-payload/SKILL.md (base64):1:1  SG-EVA-003  AST07
  ↳ recovered from examples/evasion/encoded-payload/SKILL.md
  ```

  The reader can always trace a finding back to the exact file, and for encoded
  payloads to the line of the blob.

## What is caught today

| Evasion | Rule | Notes |
|---|---|---|
| Blank-line / single-line flood | `SG-EVA-001` | Fires on runs of ≥ 50 blank lines or lines ≥ 20,000 chars. |
| Zero-width and bidi characters | `SG-INJ-007` | Text is deobfuscated before matching, so `ig␣nore` still matches, and the evasion is named on the finding. |
| Homoglyph substitution | `SG-EVA-002` | Cyrillic, Greek and Latin look-alikes are folded to ASCII. |
| Base64 / hex / percent payloads | `SG-EVA-003`, `SG-EVA-004` | Blobs that decode to printable text are extracted and scanned; nested encodings are decoded one layer deeper. |
| Unicode tag smuggling | `SG-OBF-001` | |
| Escape sequences | `SG-OBF-003` | Decoded into the deobfuscated view. |
| Payloads in `.docx` / `.zip` / `.jar` | `SG-ART-003`, `SG-EVA-003` | Archive entries are opened and scanned; nested archives recurse. |
| Poisoned `.pyc` next to source | `SG-ART-001` | Compiled artefacts with no reviewable source are flagged. |
| Dangerous strings in binaries | `SG-ART-002` | Printable strings (ASCII and UTF-16LE, both alignments) are extracted and matched. |
| Registry / index rewriting | `SG-SC-006` | `.npmrc`, `pip.conf`, `.gemrc`, `gem sources`, `go env -w GOPROXY`, … |
| `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` | `SG-SC-007` | |
| Runtime compilation | `SG-SC-008` | `gcc -shared`, `cc <<EOF`, `rustc`, `go build` … |
| TLS-verification disabling | `SG-SC-009` | |
| Hidden files | — | Scanned deliberately. The default exclusion list only covers build and vendor directories. |

## Try to bypass it

The fixtures are committed so anyone can reproduce the result:

```bash
node bin/skillsleuth.js examples/evasion
```

The adversarial cases from the Trail of Bits report are asserted in
[`test/evasion.test.js`](../test/evasion.test.js). If a change weakens
detection, CI fails.

## Adding coverage

1. Add a fixture under `examples/evasion/` (or a unit fixture in the test file).
2. Add or extend a rule — see [`docs/ARCHITECTURE.md`](ARCHITECTURE.md).
3. Add an assertion to `test/evasion.test.js`.
4. Open a PR.

## Honest limits

Evasion resistance is a direction, not a finish line. Specifically:

- **Unknown encodings are not decoded.** A payload wrapped in a scheme SkillSleuth
  does not implement (a custom cipher, a compressed-then-encrypted blob) will not
  be recovered. The `SG-OBF-*` high-entropy rules raise the signal, but they do
  not decode it.
- **Binaries are string-scanned, not disassembled.** There is no decompiler here.
  A payload that only assembles at runtime is invisible to strings.
- **Nested archives are bounded.** Depth and size are capped to prevent zip
  bombs, so a sufficiently deep nesting can hide content. This is a deliberate
  trade against denial of service.
- **A convincing argument still wins.** Static analysis cannot distinguish a
  legitimate instruction from a manipulative one if both are plain prose. That is
  a model-level problem, and SkillSleuth does not pretend to solve it.

The point is not to be unbeatable. It is to make the *cheap* bypasses — the ones
that worked on everything else — stop being cheap.
