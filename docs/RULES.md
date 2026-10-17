# Rule reference

SkillGuard ships **48 rules** across 9 categories. This file is generated from the source by `node scripts/generate-rules-doc.js`.

## Severity and scoring

| Severity | Weight | Typical meaning |
|---|---:|---|
| critical | 45 | Direct data theft, destructive or deceptive behaviour |
| high | 20 | Dangerous capability or clear manipulation |
| medium | 8 | Risky pattern that needs review |
| low | 3 | Hygiene issue |
| info | 0 | Informational only |

A skill's score is `min(100, Σ weight × confidence)`, where confidence is `high = 1`, `medium = 0.7`, `low = 0.4`. A single critical finding always produces a **FAIL** verdict, and any high or medium finding produces at least **REVIEW**.

## injection (7)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-INJ-001` | high | AST01 — Malicious or injection-bearing instructions | Attempts to override prior instructions |
| `SG-INJ-002` | high | AST01 — Malicious or injection-bearing instructions | Persona hijack or jailbreak phrasing |
| `SG-INJ-003` | critical | AST01 — Malicious or injection-bearing instructions | Instructions to conceal activity from the user |
| `SG-INJ-004` | critical | AST01 — Malicious or injection-bearing instructions | Instructions to bypass approvals or safety checks |
| `SG-INJ-005` | medium | AST01 — Malicious or injection-bearing instructions | Possible trigger phrase or conditional backdoor |
| `SG-INJ-006` | high | AST01 — Malicious or injection-bearing instructions | Attempts to reveal or leak the system prompt |
| `SG-INJ-007` | high | AST01 — Malicious or injection-bearing instructions | Invisible or zero-width characters inside instructions |

### `SG-INJ-001` — Attempts to override prior instructions

**Severity:** high · **Confidence:** high · **Category:** injection · **OWASP:** AST01

Contains language instructing the agent to ignore, discard or override its existing instructions, the system prompt, or the user.

**Fix:** Remove the override language. A legitimate skill complements the agent instructions; it never replaces them.

### `SG-INJ-002` — Persona hijack or jailbreak phrasing

**Severity:** high · **Confidence:** high · **Category:** injection · **OWASP:** AST01

Attempts to reassign the agent a new identity or unlock unrestricted behaviour ("you are now", "developer mode", "act as").

**Fix:** Describe the task, not a new identity. Remove jailbreak framing entirely.

### `SG-INJ-003` — Instructions to conceal activity from the user

**Severity:** critical · **Confidence:** high · **Category:** injection · **OWASP:** AST01

Tells the agent to hide what it is doing, or to act without telling the user. Legitimate skills never need secrecy.

**Fix:** Delete the concealment instruction. Transparency is required for any skill that acts on a user system.

### `SG-INJ-004` — Instructions to bypass approvals or safety checks

**Severity:** critical · **Confidence:** high · **Category:** injection · **OWASP:** AST01

Asks the agent to skip confirmation, disable guardrails, or auto-approve actions. This removes the human control that keeps agents safe.

**Fix:** Remove the instruction. Keep human-in-the-loop confirmation for any impactful action.

### `SG-INJ-005` — Possible trigger phrase or conditional backdoor

**Severity:** medium · **Confidence:** medium · **Category:** injection · **OWASP:** AST01

Behaviour gated on a specific phrase the user chooses. Common in backdoor attacks where the skill stays dormant until a keyword appears.

**Fix:** Avoid behaviour gated on secret trigger words. State the condition explicitly and verifiably.

### `SG-INJ-006` — Attempts to reveal or leak the system prompt

**Severity:** high · **Confidence:** high · **Category:** injection · **OWASP:** AST01

Asks the agent to print or transmit its system prompt, hidden instructions or internal configuration.

**Fix:** Remove the request. Extract the model configuration through supported APIs instead.

### `SG-INJ-007` — Invisible or zero-width characters inside instructions

**Severity:** high · **Confidence:** high · **Category:** injection · **OWASP:** AST01

Contains zero-width or bidirectional control characters. These can hide instructions from human review while the model still reads them.

**Fix:** Strip all invisible characters from the skill. Text should be plain, visible and reviewable.

## credentials (4)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-CRED-001` | critical | AST03 — Credential and secret access | Access to sensitive credential files |
| `SG-CRED-002` | high | AST03 — Credential and secret access | Reads secret environment variables |
| `SG-CRED-003` | medium | AST03 — Credential and secret access | Broad environment dump |
| `SG-CRED-004` | high | AST03 — Credential and secret access | Access to the SSH agent or git credential helper |

### `SG-CRED-001` — Access to sensitive credential files

**Severity:** critical · **Confidence:** high · **Category:** credentials · **OWASP:** AST03

References files that hold credentials, private keys or session tokens (SSH, AWS, .env, npm, Docker, browser cookies, keychains).

**Fix:** Never read credential stores. If a secret is required, ask the user to provide it explicitly via an environment variable you document.

### `SG-CRED-002` — Reads secret environment variables

**Severity:** high · **Confidence:** high · **Category:** credentials · **OWASP:** AST03

Reads or prints environment variables that typically contain secrets (tokens, API keys, passwords).

**Fix:** Reference only the specific, non-secret variables you need. Never enumerate the environment or match variables by wildcard.

### `SG-CRED-003` — Broad environment dump

**Severity:** medium · **Confidence:** medium · **Category:** credentials · **OWASP:** AST03

Dumps the entire environment, which commonly leaks secrets into agent transcripts and logs.

**Fix:** Read individual variables that are documented and non-sensitive.

### `SG-CRED-004` — Access to the SSH agent or git credential helper

**Severity:** high · **Confidence:** medium · **Category:** credentials · **OWASP:** AST03

Uses the SSH agent socket or git credential helpers to obtain credentials the user did not hand over.

**Fix:** Use a scoped, read-only deploy key that the user explicitly provides.

## exfiltration (6)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-EXFIL-001` | high | AST04 — Data exfiltration | Uploads data to a remote endpoint |
| `SG-EXFIL-002` | critical | AST04 — Data exfiltration | Posts to a known exfiltration sink |
| `SG-EXFIL-003` | high | AST04 — Data exfiltration | Encodes data before sending it |
| `SG-EXFIL-004` | critical | AST04 — Data exfiltration | Pipes secrets straight into the network |
| `SG-EXFIL-005` | critical | AST04 — Data exfiltration | Raw socket or reverse-shell style connection |
| `SG-EXFIL-006` | high | AST04 — Data exfiltration | DNS-based exfiltration pattern |

### `SG-EXFIL-001` — Uploads data to a remote endpoint

**Severity:** high · **Confidence:** medium · **Category:** exfiltration · **OWASP:** AST04

Sends a request body or uploads a file to a remote host. Combined with credential access this is data theft.

**Fix:** State exactly what is sent and to which host. Prefer hosts the user configured themselves.

### `SG-EXFIL-002` — Posts to a known exfiltration sink

**Severity:** critical · **Confidence:** high · **Category:** exfiltration · **OWASP:** AST04

References a service commonly used to receive stolen data (webhooks, request bins, tunnelling and collaborator domains).

**Fix:** Remove the sink. If telemetry is intended, use a first-party endpoint the user can see and disable.

### `SG-EXFIL-003` — Encodes data before sending it

**Severity:** high · **Confidence:** medium · **Category:** exfiltration · **OWASP:** AST04

Base64-encodes or compresses content next to a network call — a common way to smuggle secrets past review.

**Fix:** Never encode data for transmission. Send plain, reviewable payloads to documented endpoints.

### `SG-EXFIL-004` — Pipes secrets straight into the network

**Severity:** critical · **Confidence:** high · **Category:** exfiltration · **OWASP:** AST04

Pipes environment variables or .env contents into a network client. There is no legitimate reason to do this.

**Fix:** Remove entirely.

### `SG-EXFIL-005` — Raw socket or reverse-shell style connection

**Severity:** critical · **Confidence:** high · **Category:** exfiltration · **OWASP:** AST04

Uses netcat, /dev/tcp, or a similar raw socket to open an outbound connection or shell.

**Fix:** Remove. Use documented HTTP APIs with explicit consent.

### `SG-EXFIL-006` — DNS-based exfiltration pattern

**Severity:** high · **Confidence:** medium · **Category:** exfiltration · **OWASP:** AST04

Builds a DNS lookup from computed data, a classic low-and-slow exfiltration channel.

**Fix:** Remove dynamic DNS lookups that embed data.

## execution (8)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-EXEC-001` | critical | AST05 — Unsafe or destructive execution | Remote code executed through a pipe |
| `SG-EXEC-002` | high | AST05 — Unsafe or destructive execution | Dynamic code evaluation |
| `SG-EXEC-003` | critical | AST05 — Unsafe or destructive execution | Destructive filesystem command |
| `SG-EXEC-004` | high | AST05 — Unsafe or destructive execution | Privilege escalation |
| `SG-EXEC-005` | high | AST05 — Unsafe or destructive execution | Persistence or system modification |
| `SG-EXEC-006` | high | AST05 — Unsafe or destructive execution | Destructive or history-rewriting git command |
| `SG-EXEC-007` | critical | AST05 — Unsafe or destructive execution | Disables logging or security controls |
| `SG-EXEC-008` | medium | AST05 — Unsafe or destructive execution | Process termination |

### `SG-EXEC-001` — Remote code executed through a pipe

**Severity:** critical · **Confidence:** high · **Category:** execution · **OWASP:** AST05

Downloads a script from the network and executes it directly (curl | sh). The remote content is unpinned and unauditable.

**Fix:** Vendor the script, pin it to a checksum, and review it before running.

### `SG-EXEC-002` — Dynamic code evaluation

**Severity:** high · **Confidence:** medium · **Category:** execution · **OWASP:** AST05

Evaluates dynamically built code (eval/exec/Function), which hides what actually runs.

**Fix:** Avoid dynamic evaluation in skills. Write explicit, reviewable code.

### `SG-EXEC-003` — Destructive filesystem command

**Severity:** critical · **Confidence:** high · **Category:** execution · **OWASP:** AST05

Deletes or overwrites data at a broad scope (root, home, wildcard, block devices).

**Fix:** Never target broad paths. Operate on explicit, user-named directories only.

### `SG-EXEC-004` — Privilege escalation

**Severity:** high · **Confidence:** high · **Category:** execution · **OWASP:** AST05

Requests elevated privileges or changes permissions broadly.

**Fix:** Skills should run with the least privilege needed and never elevate silently.

### `SG-EXEC-005` — Persistence or system modification

**Severity:** high · **Confidence:** high · **Category:** execution · **OWASP:** AST05

Modifies shell profiles, cron, launch agents, system services or host files to survive the session.

**Fix:** A skill should not install persistence. Ask the user to opt in explicitly outside the skill.

### `SG-EXEC-006` — Destructive or history-rewriting git command

**Severity:** high · **Confidence:** medium · **Category:** execution · **OWASP:** AST05

Force-pushes, hard-resets or deletes git history, which can destroy the user's work irreversibly.

**Fix:** Avoid rewriting history. If needed, make it an explicit, confirmed step.

### `SG-EXEC-007` — Disables logging or security controls

**Severity:** critical · **Confidence:** high · **Category:** execution · **OWASP:** AST05

Turns off shell history, security policy or code-signing checks — behaviour whose only purpose is to avoid detection.

**Fix:** Remove. Never disable auditing or security enforcement from a skill.

### `SG-EXEC-008` — Process termination

**Severity:** medium · **Confidence:** low · **Category:** execution · **OWASP:** AST05

Kills processes. Sometimes legitimate, but easy to misuse; confirm scope before running.

**Fix:** Target a specific PID the user provided instead of matching process names.

## supply-chain (5)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-SC-001` | high | AST06 — Supply-chain risk | Installs dependencies from a URL or VCS |
| `SG-SC-002` | critical | AST06 — Supply-chain risk | Downloads and unpacks remote code |
| `SG-SC-003` | high | AST06 — Supply-chain risk | Fetches code from a paste or raw-content host at runtime |
| `SG-SC-004` | medium | AST06 — Supply-chain risk | Runs unpinned packages on the fly |
| `SG-SC-005` | high | AST06 — Supply-chain risk | Points the package manager at a non-default registry |

### `SG-SC-001` — Installs dependencies from a URL or VCS

**Severity:** high · **Confidence:** high · **Category:** supply-chain · **OWASP:** AST06

Installs packages from a URL, git remote or alternate registry instead of the pinned registry.

**Fix:** Pin dependencies to a version from the default registry and commit a lockfile.

### `SG-SC-002` — Downloads and unpacks remote code

**Severity:** critical · **Confidence:** high · **Category:** supply-chain · **OWASP:** AST06

Fetches an archive or binary and unpacks or installs it — the classic delivery step for a malicious payload.

**Fix:** Vendor the artifact, pin a checksum, and verify the signature.

### `SG-SC-003` — Fetches code from a paste or raw-content host at runtime

**Severity:** high · **Confidence:** medium · **Category:** supply-chain · **OWASP:** AST06

Pulls scripts from raw repositories, gists or paste services while running. Content can change after review.

**Fix:** Inline or vendor the code so what the user reviewed is what runs.

### `SG-SC-004` — Runs unpinned packages on the fly

**Severity:** medium · **Confidence:** medium · **Category:** supply-chain · **OWASP:** AST06

Executes a package without pinning a version (npx -y, uvx, pipx run). The resolved code can change between runs.

**Fix:** Pin the exact version, for example npx package@1.2.3.

### `SG-SC-005` — Points the package manager at a non-default registry

**Severity:** high · **Confidence:** medium · **Category:** supply-chain · **OWASP:** AST06

Overrides the registry or index URL, which redirects installs to an attacker-controlled source.

**Fix:** Use the default registry. If a mirror is truly required, document it and pin it.

## obfuscation (5)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-OBF-001` | critical | AST07 — Obfuscation | Unicode tag characters hidden in text |
| `SG-OBF-002` | high | AST07 — Obfuscation | Long encoded blob |
| `SG-OBF-003` | high | AST07 — Obfuscation | Hex or escape-sequence encoded payload |
| `SG-OBF-004` | low | AST07 — Obfuscation | Abnormally long line |
| `SG-OBF-005` | low | AST07 — Obfuscation | High-entropy token (possible encoded secret or payload) |

### `SG-OBF-001` — Unicode tag characters hidden in text

**Severity:** critical · **Confidence:** high · **Category:** obfuscation · **OWASP:** AST07

Contains Unicode "tag" characters, which are invisible and can smuggle an entire hidden instruction set past human review.

**Fix:** Strip the tag characters. There is no legitimate use in a skill.

### `SG-OBF-002` — Long encoded blob

**Severity:** high · **Confidence:** medium · **Category:** obfuscation · **OWASP:** AST07

Contains a long base64-looking blob that could encode a hidden payload or instruction.

**Fix:** Remove the blob or replace it with reviewable source. Document any required binary asset.

### `SG-OBF-003` — Hex or escape-sequence encoded payload

**Severity:** high · **Confidence:** medium · **Category:** obfuscation · **OWASP:** AST07

Contains long runs of \x or \u escapes, typically an encoded payload rather than readable code.

**Fix:** Replace with readable, reviewable code.

### `SG-OBF-004` — Abnormally long line

**Severity:** low · **Confidence:** low · **Category:** obfuscation · **OWASP:** AST07

Contains a very long single line, which is often used to push content out of view during review.

**Fix:** Wrap the content so it can be reviewed normally.

### `SG-OBF-005` — High-entropy token (possible encoded secret or payload)

**Severity:** low · **Confidence:** low · **Category:** obfuscation · **OWASP:** AST07

Contains a random-looking string that may be an encoded payload or an embedded credential.

**Fix:** Confirm the string is intentional. Replace embedded secrets with environment variables.

## metadata (6)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-META-001` | low | AST08 — Over-broad permissions and metadata hygiene | Missing skill description |
| `SG-META-002` | high | AST08 — Over-broad permissions and metadata hygiene | Wildcard or unrestricted tool grants |
| `SG-META-003` | medium | AST08 — Over-broad permissions and metadata hygiene | Declares broad runtime scope |
| `SG-META-004` | medium | AST08 — Over-broad permissions and metadata hygiene | Skill claims to always run or auto-apply |
| `SG-META-005` | low | AST08 — Over-broad permissions and metadata hygiene | Skill has no frontmatter |
| `SG-META-006` | low | AST08 — Over-broad permissions and metadata hygiene | Skill name does not match its directory |

### `SG-META-001` — Missing skill description

**Severity:** low · **Confidence:** high · **Category:** metadata · **OWASP:** AST08

The SKILL.md has no description in frontmatter, so the agent cannot judge when the skill applies and the user cannot judge intent.

**Fix:** Add a `description` in frontmatter that states exactly what the skill does and when it triggers.

### `SG-META-002` — Wildcard or unrestricted tool grants

**Severity:** high · **Confidence:** high · **Category:** metadata · **OWASP:** AST08

Frontmatter requests wildcard permissions (for example `allowed-tools: *`), granting the skill far more capability than it needs.

**Fix:** List only the specific tools the skill uses, with the narrowest scopes you can.

### `SG-META-003` — Declares broad runtime scope

**Severity:** medium · **Confidence:** medium · **Category:** metadata · **OWASP:** AST08

Frontmatter declares broad network, shell or filesystem access at the root or for everything.

**Fix:** Narrow the declared scope, or drop the declaration if the skill does not need it.

### `SG-META-004` — Skill claims to always run or auto-apply

**Severity:** medium · **Confidence:** medium · **Category:** metadata · **OWASP:** AST08

Claims to run on every task or always take effect, which makes the skill permanently active beyond the user's intent.

**Fix:** Make the skill apply only when its trigger conditions are clearly met.

### `SG-META-005` — Skill has no frontmatter

**Severity:** low · **Confidence:** high · **Category:** metadata · **OWASP:** AST08

The SKILL.md has no frontmatter block, so it cannot declare a name, description or scoped permissions.

**Fix:** Add a frontmatter block with at least `name` and `description`.

### `SG-META-006` — Skill name does not match its directory

**Severity:** low · **Confidence:** medium · **Category:** metadata · **OWASP:** AST08

The declared name differs from the folder name, which makes review and pinning harder.

**Fix:** Keep the frontmatter `name` identical to the directory name.

## secrets (4)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-SEC-001` | critical | AST09 — Secret leakage in the skill itself | Hardcoded API key or access token |
| `SG-SEC-002` | critical | AST09 — Secret leakage in the skill itself | Private key material |
| `SG-SEC-003` | high | AST09 — Secret leakage in the skill itself | Hardcoded credential assignment |
| `SG-SEC-004` | critical | AST09 — Secret leakage in the skill itself | Connection string containing credentials |

### `SG-SEC-001` — Hardcoded API key or access token

**Severity:** critical · **Confidence:** high · **Category:** secrets · **OWASP:** AST09

Contains what appears to be a live credential for a well-known provider.

**Fix:** Revoke the key immediately, then load it from an environment variable the user provides.

### `SG-SEC-002` — Private key material

**Severity:** critical · **Confidence:** high · **Category:** secrets · **OWASP:** AST09

Contains a private key block. This should never be stored in a skill.

**Fix:** Remove the key, rotate it, and reference a path the user controls.

### `SG-SEC-003` — Hardcoded credential assignment

**Severity:** high · **Confidence:** medium · **Category:** secrets · **OWASP:** AST09

Assigns a literal value to a password, secret or token field.

**Fix:** Read the value from the environment or a secret manager; never commit it.

### `SG-SEC-004` — Connection string containing credentials

**Severity:** critical · **Confidence:** high · **Category:** secrets · **OWASP:** AST09

A database or broker URL embeds a username and password inline.

**Fix:** Move the password to an environment variable and reference it in the URL at runtime.

## assets (3)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-ASSET-001` | high | AST10 — Bundled assets | Executable binary bundled in the skill |
| `SG-ASSET-002` | medium | AST10 — Bundled assets | High-risk script or package file type |
| `SG-ASSET-003` | info | AST10 — Bundled assets | Archive bundled in the skill |

### `SG-ASSET-001` — Executable binary bundled in the skill

**Severity:** high · **Confidence:** high · **Category:** assets · **OWASP:** AST10

Ships a compiled executable. Its behaviour cannot be reviewed as source, and it runs with the user's privileges.

**Fix:** Ship source instead. If a binary is unavoidable, document the build and publish checksums.

### `SG-ASSET-002` — High-risk script or package file type

**Severity:** medium · **Confidence:** medium · **Category:** assets · **OWASP:** AST10

Bundles a script or package type that executes automatically or is commonly used to deliver payloads.

**Fix:** Explain why the file is needed and make it reviewable. Prefer plain, documented scripts.

### `SG-ASSET-003` — Archive bundled in the skill

**Severity:** info · **Confidence:** medium · **Category:** assets · **OWASP:** AST10

Contains a compressed archive whose contents are not visible during review.

**Fix:** Expand and commit the contents, or document the archive and its checksum.

---

_Generated from SkillGuard v0.1.0._
