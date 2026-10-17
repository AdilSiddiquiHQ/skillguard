# Rule reference

SkillGuard ships **75 rules** across 13 categories. This file is generated from the source by `node scripts/generate-rules-doc.js`.

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
| `SG-INJ-004` | high | AST01 — Malicious or injection-bearing instructions | Instructions to bypass approvals or safety checks |
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

**Severity:** high · **Confidence:** high · **Category:** injection · **OWASP:** AST01

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
| `SG-CRED-002` | high | AST03 — Credential and secret access | Prints or forwards a secret environment variable |
| `SG-CRED-003` | medium | AST03 — Credential and secret access | Broad environment dump |
| `SG-CRED-004` | high | AST03 — Credential and secret access | Access to the SSH agent or git credential helper |

### `SG-CRED-001` — Access to sensitive credential files

**Severity:** critical · **Confidence:** high · **Category:** credentials · **OWASP:** AST03

Reads, copies or transmits files that hold credentials, private keys or session tokens (SSH, AWS, .env, npm, Docker, browser cookies, keychains).

**Fix:** Never read credential stores. If a secret is required, ask the user to provide it explicitly via an environment variable you document.

### `SG-CRED-002` — Prints or forwards a secret environment variable

**Severity:** high · **Confidence:** high · **Category:** credentials · **OWASP:** AST03

Prints, dumps or pipes an environment variable that holds a secret (token, API key, password). Naming such a variable is normal; echoing or forwarding its value is not.

**Fix:** Never print or transmit secret variables. Read only the specific, non-secret values you need, and keep secret handling inside the API client.

### `SG-CRED-003` — Broad environment dump

**Severity:** medium · **Confidence:** medium · **Category:** credentials · **OWASP:** AST03

Dumps, prints or forwards the entire environment, which commonly leaks secrets into agent transcripts and logs.

**Fix:** Read individual variables that are documented and non-sensitive.

### `SG-CRED-004` — Access to the SSH agent or git credential helper

**Severity:** high · **Confidence:** medium · **Category:** credentials · **OWASP:** AST03

Uses the SSH agent socket or git credential helpers to obtain credentials the user did not hand over.

**Fix:** Use a scoped, read-only deploy key that the user explicitly provides.

## exfiltration (6)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-EXFIL-001` | medium | AST04 — Data exfiltration | Uploads data to a remote endpoint |
| `SG-EXFIL-002` | critical | AST04 — Data exfiltration | Posts to a known exfiltration sink |
| `SG-EXFIL-003` | high | AST04 — Data exfiltration | Encodes data before sending it |
| `SG-EXFIL-004` | critical | AST04 — Data exfiltration | Pipes secrets straight into the network |
| `SG-EXFIL-005` | critical | AST04 — Data exfiltration | Raw socket or reverse-shell style connection |
| `SG-EXFIL-006` | high | AST04 — Data exfiltration | DNS-based exfiltration pattern |

### `SG-EXFIL-001` — Uploads data to a remote endpoint

**Severity:** medium · **Confidence:** medium · **Category:** exfiltration · **OWASP:** AST04

Sends a request body or uploads a file to an external host, or uploads credentials and local files. A relative path or a localhost API call is not reported.

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
| `SG-EXEC-004` | medium | AST05 — Unsafe or destructive execution | Privilege escalation |
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

**Severity:** medium · **Confidence:** high · **Category:** execution · **OWASP:** AST05

Runs a command with elevated privileges. A documented install step is an advisory; escalating to modify system state is serious.

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

## supply-chain (10)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-SC-001` | high | AST06 — Supply-chain risk | Installs dependencies from a URL or VCS |
| `SG-SC-002` | critical | AST06 — Supply-chain risk | Downloads and unpacks remote code |
| `SG-SC-003` | high | AST06 — Supply-chain risk | Fetches code from a paste or raw-content host at runtime |
| `SG-SC-004` | medium | AST06 — Supply-chain risk | Runs unpinned packages on the fly |
| `SG-SC-005` | high | AST06 — Supply-chain risk | Points the package manager at a non-default registry |
| `SG-SC-006` | high | AST06 — Supply-chain risk | Rewrites package-manager registry configuration |
| `SG-SC-007` | critical | AST05 — Unsafe or destructive execution | Injects a dynamic library into other processes |
| `SG-SC-008` | high | AST05 — Unsafe or destructive execution | Compiles and loads code at runtime |
| `SG-SC-009` | high | AST06 — Supply-chain risk | Disables TLS or certificate verification |
| `SG-SC-010` | medium | AST06 — Supply-chain risk | Installs software outside the project directory |

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

### `SG-SC-006` — Rewrites package-manager registry configuration

**Severity:** high · **Confidence:** high · **Category:** supply-chain · **OWASP:** AST06

Writes a registry or index setting into a package-manager config file (.npmrc, .yarnrc, pip.conf, .gemrc, settings.xml). This is the exact technique used in a documented scanner bypass: every future install silently routes through an attacker-controlled mirror.

**Fix:** Never modify registry configuration from a skill. Use the default registry, or have the user opt in explicitly.

### `SG-SC-007` — Injects a dynamic library into other processes

**Severity:** critical · **Confidence:** high · **Category:** supply-chain · **OWASP:** AST05

Uses LD_PRELOAD, DYLD_INSERT_LIBRARIES or a similar mechanism to inject a library into another process. It hijacks code you did not write and cannot see.

**Fix:** Remove. There is no reason for a skill to inject libraries into other processes.

### `SG-SC-008` — Compiles and loads code at runtime

**Severity:** high · **Confidence:** medium · **Category:** supply-chain · **OWASP:** AST05

Invokes a compiler or linker to build a library from embedded source, then loads it. This is a documented technique for shipping a payload as a harmless-looking string and a way to evade review entirely.

**Fix:** Ship source the agent interprets, never a build step that produces a binary at runtime.

### `SG-SC-009` — Disables TLS or certificate verification

**Severity:** high · **Confidence:** high · **Category:** supply-chain · **OWASP:** AST06

Turns off TLS verification (NODE_TLS_REJECT_UNAUTHORIZED, strict-ssl=false, --insecure, GIT_SSL_NO_VERIFY). This enables man-in-the-middle tampering with everything the agent downloads.

**Fix:** Keep certificate verification on. Fix the underlying trust problem instead of disabling the check.

### `SG-SC-010` — Installs software outside the project directory

**Severity:** medium · **Confidence:** medium · **Category:** supply-chain · **OWASP:** AST06

Installs packages system-wide or globally, changing the environment for every project on the machine and expanding the blast radius of the skill.

**Fix:** Install into a project-local, disposable environment (a virtualenv or node_modules).

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

## evasion (5)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-EVA-001` | critical | AST07 — Obfuscation | Context-flood or padding attack |
| `SG-EVA-002` | medium | AST07 — Obfuscation | Homoglyph obfuscation of text |
| `SG-EVA-003` | critical | AST07 — Obfuscation | Dangerous command recovered from encoded or embedded content |
| `SG-EVA-004` | critical | AST02 — Untrusted dependency or tool instructions | Agent instructions hidden in encoded or embedded content |
| `SG-EVA-005` | medium | AST02 — Untrusted dependency or tool instructions | Instructions concealed in HTML or Markdown comments |

### `SG-EVA-001` — Context-flood or padding attack

**Severity:** critical · **Confidence:** high · **Category:** evasion · **OWASP:** AST07

The file contains an enormous run of blank lines or a single giant line. This is the documented trick for pushing a payload past a scanner's truncation limit while it stays invisible to a human scrolling the page.

**Fix:** Remove the padding. If the content is genuinely large, split it into named, reviewable sections.

### `SG-EVA-002` — Homoglyph obfuscation of text

**Severity:** medium · **Confidence:** medium · **Category:** evasion · **OWASP:** AST07

Word characters are replaced with visually identical Unicode look-alikes (for example Cyrillic "а" for Latin "a"). This defeats naive pattern matching while reading identically to a human.

**Fix:** Use plain ASCII. Any non-ASCII look-alike inside a command or keyword is almost certainly deliberate.

### `SG-EVA-003` — Dangerous command recovered from encoded or embedded content

**Severity:** critical · **Confidence:** high · **Category:** evasion · **OWASP:** AST07

A base64, hex or percent-encoded blob (or a file inside an archive or document) decodes to a command that downloads, executes or deletes content. The encoding exists to hide it.

**Fix:** Never ship encoded executables or scripts inside a skill. Inline the real, reviewable source.

### `SG-EVA-004` — Agent instructions hidden in encoded or embedded content

**Severity:** critical · **Confidence:** high · **Category:** evasion · **OWASP:** AST02

An encoded blob or an embedded document decodes to natural-language instructions aimed at the agent, such as overriding prior instructions or sending data away. Humans never see it.

**Fix:** Keep every instruction in the plain SKILL.md body where it can be reviewed. Remove the encoded blob.

### `SG-EVA-005` — Instructions concealed in HTML or Markdown comments

**Severity:** medium · **Confidence:** medium · **Category:** evasion · **OWASP:** AST02

Instruction-like text is hidden inside an HTML or Markdown comment. The rendered skill looks benign while the model still reads the comment.

**Fix:** Remove hidden comments. All instructions belong in the visible body.

## artifacts (4)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-ART-001` | critical | AST06 — Supply-chain risk | Compiled artefact with no matching source |
| `SG-ART-002` | high | AST06 — Supply-chain risk | Suspicious strings inside a binary artefact |
| `SG-ART-003` | high | AST06 — Supply-chain risk | Executable or script payload inside an archive |
| `SG-ART-004` | medium | AST06 — Supply-chain risk | Opaque file type that cannot be reviewed |

### `SG-ART-001` — Compiled artefact with no matching source

**Severity:** critical · **Confidence:** high · **Category:** artifacts · **OWASP:** AST06

The skill ships compiled bytecode or a shared library (for example a .pyc) without the source file it was built from. This is the exact shape of the poisoned-bytecode supply-chain attack: the bytecode contains behaviour the visible source does not.

**Fix:** Delete compiled artefacts. Ship readable source only, and let the agent interpret it.

### `SG-ART-002` — Suspicious strings inside a binary artefact

**Severity:** high · **Confidence:** medium · **Category:** artifacts · **OWASP:** AST06

A bundled binary contains strings strongly associated with payloads and post-exploitation: library injection, reverse shells, credential paths or inline base64 decoding.

**Fix:** Remove the binary, or document and vendor it from a pinned, signed upstream release. Never trust a binary you cannot read.

### `SG-ART-003` — Executable or script payload inside an archive

**Severity:** high · **Confidence:** high · **Category:** artifacts · **OWASP:** AST06

An archive or document (such as .docx, .zip, .jar) contains an executable or script entry. This is how a payload rides along inside a file a reviewer would open as text.

**Fix:** Rebuild the document without embedded scripts, or ship the payload as explicit, reviewable source.

### `SG-ART-004` — Opaque file type that cannot be reviewed

**Severity:** medium · **Confidence:** medium · **Category:** artifacts · **OWASP:** AST06

The skill ships one or more files that a human cannot read and a code scanner cannot fully analyse. Opaque blobs defeat review and are outside the Agent Skills specification.

**Fix:** Keep skills to reviewable text. If a binary asset is unavoidable, pin it to a checksum and explain why.

## mcp (7)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-MCP-001` | critical | AST06 — Supply-chain risk | MCP server pipes remote code into a shell |
| `SG-MCP-002` | high | AST06 — Supply-chain risk | MCP server runs an unpinned package |
| `SG-MCP-003` | high | AST04 — Data exfiltration | Secret hardcoded in MCP server environment |
| `SG-MCP-004` | critical | AST05 — Unsafe or destructive execution | MCP server launched with permission-bypass flags |
| `SG-MCP-005` | medium | AST06 — Supply-chain risk | Remote MCP server over plaintext HTTP |
| `SG-MCP-006` | high | AST03 — Credential and secret access | MCP filesystem server rooted at home or root |
| `SG-MCP-007` | medium | AST04 — Data exfiltration | MCP auto-approval or blanket trust enabled |

### `SG-MCP-001` — MCP server pipes remote code into a shell

**Severity:** critical · **Confidence:** high · **Category:** mcp · **OWASP:** AST06

An MCP server is configured to fetch a script and execute it in a shell. The code that runs is whatever the remote host serves at launch time.

**Fix:** Install the server as a pinned package, or vendor the entry point into the repository.

### `SG-MCP-002` — MCP server runs an unpinned package

**Severity:** high · **Confidence:** medium · **Category:** mcp · **OWASP:** AST06

An MCP server is launched with npx/pipx/uvx without a pinned version. The package resolved at launch can change after this configuration was reviewed.

**Fix:** Pin the exact version, for example `npx -y @scope/server@1.4.2`.

### `SG-MCP-003` — Secret hardcoded in MCP server environment

**Severity:** high · **Confidence:** medium · **Category:** mcp · **OWASP:** AST04

An MCP server entry embeds what looks like an API key or token in the configuration file, which is committed and shared.

**Fix:** Reference the value from the environment or a secret store instead of inlining it.

### `SG-MCP-004` — MCP server launched with permission-bypass flags

**Severity:** critical · **Confidence:** high · **Category:** mcp · **OWASP:** AST05

A server or harness is started with flags that disable approvals or the sandbox, removing the last human checkpoint before action.

**Fix:** Remove the bypass flag. Approvals and sandboxing are the control, not an obstacle.

### `SG-MCP-005` — Remote MCP server over plaintext HTTP

**Severity:** medium · **Confidence:** high · **Category:** mcp · **OWASP:** AST06

A remote MCP server is reached over unencrypted HTTP, so its responses can be rewritten in transit.

**Fix:** Use HTTPS, and pin the expected host.

### `SG-MCP-006` — MCP filesystem server rooted at home or root

**Severity:** high · **Confidence:** medium · **Category:** mcp · **OWASP:** AST03

A filesystem MCP server is given access to the whole home directory or filesystem, so any instruction the agent reads can reach every file the user owns.

**Fix:** Scope the server to the specific project directory it needs.

### `SG-MCP-007` — MCP auto-approval or blanket trust enabled

**Severity:** medium · **Confidence:** medium · **Category:** mcp · **OWASP:** AST04

The configuration pre-approves tool calls or marks servers as trusted, so the agent can act without asking.

**Fix:** Require approval for tool calls, especially from servers that touch the network or the filesystem.

## plugin (3)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-PLUG-001` | high | AST05 — Unsafe or destructive execution | Plugin hook executes a shell command |
| `SG-PLUG-002` | critical | AST06 — Supply-chain risk | Plugin hook downloads and runs remote code |
| `SG-PLUG-003` | medium | AST04 — Data exfiltration | Plugin hook runs on every event without a matcher |

### `SG-PLUG-001` — Plugin hook executes a shell command

**Severity:** high · **Confidence:** high · **Category:** plugin · **OWASP:** AST05

The plugin registers a lifecycle hook that runs a shell command. Hooks execute automatically, so installing the plugin runs this code without a per-action prompt.

**Fix:** Remove hooks you cannot fully read, or make them a no-op. Prefer explicit user-invoked commands over automatic hooks.

### `SG-PLUG-002` — Plugin hook downloads and runs remote code

**Severity:** critical · **Confidence:** high · **Category:** plugin · **OWASP:** AST06

A lifecycle hook fetches a script from the network and executes it. The hook runs automatically, so this is unattended remote code execution.

**Fix:** Vendor the script, pin it to a checksum, and run it only on explicit user action.

### `SG-PLUG-003` — Plugin hook runs on every event without a matcher

**Severity:** medium · **Confidence:** medium · **Category:** plugin · **OWASP:** AST04

A tool hook has no matcher, so it runs on every tool call the agent makes rather than a narrow, named tool. This maximises the blast radius of the hook.

**Fix:** Add a matcher that limits the hook to the specific tools it needs.

## metadata (9)

| Rule | Severity | OWASP | What it detects |
|---|---|---|---|
| `SG-META-001` | low | AST08 — Over-broad permissions and metadata hygiene | Missing skill description |
| `SG-META-002` | high | AST08 — Over-broad permissions and metadata hygiene | Wildcard or unrestricted tool grants |
| `SG-META-003` | medium | AST08 — Over-broad permissions and metadata hygiene | Declares broad runtime scope |
| `SG-META-004` | medium | AST08 — Over-broad permissions and metadata hygiene | Skill claims to always run or auto-apply |
| `SG-META-005` | low | AST08 — Over-broad permissions and metadata hygiene | Skill has no frontmatter |
| `SG-META-006` | low | AST08 — Over-broad permissions and metadata hygiene | Skill name does not match its directory |
| `SG-META-007` | high | AST08 — Over-broad permissions and metadata hygiene | Body uses a capability the frontmatter does not grant |
| `SG-META-008` | high | AST02 — Untrusted dependency or tool instructions | Frontmatter metadata contains instruction-like text |
| `SG-META-009` | low | AST08 — Over-broad permissions and metadata hygiene | Non-standard or oversized frontmatter fields |

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

### `SG-META-007` — Body uses a capability the frontmatter does not grant

**Severity:** high · **Confidence:** medium · **Category:** metadata · **OWASP:** AST08

The skill declares an explicit `allowed-tools` list, but its body performs an action (running a shell, reaching the network, writing files) that the declared list does not cover. The stated permissions do not match the behaviour.

**Fix:** Either grant the tool the skill actually needs, or remove the action from the body. Declared scope should match behaviour.

### `SG-META-008` — Frontmatter metadata contains instruction-like text

**Severity:** high · **Confidence:** medium · **Category:** metadata · **OWASP:** AST02

The name or description carries instruction-like phrasing aimed at the agent. Frontmatter is read verbatim by the model, so it is a prompt-injection channel, not just a label.

**Fix:** Keep metadata to a plain, factual description of what the skill does.

### `SG-META-009` — Non-standard or oversized frontmatter fields

**Severity:** low · **Confidence:** medium · **Category:** metadata · **OWASP:** AST08

The frontmatter contains keys outside the Agent Skills specification, or values longer than the spec allows. Unknown keys are ignored by some harnesses and honoured by others, which makes behaviour inconsistent.

**Fix:** Stick to the documented frontmatter keys and keep the description under 1024 characters.

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

_Generated from SkillGuard v0.3.1._
