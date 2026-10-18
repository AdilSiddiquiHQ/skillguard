# Security policy

## Reporting a vulnerability

SkillSleuth is a security tool, so bypasses and false negatives matter as much
as memory-safety style bugs.

Please report privately using GitHub's [private vulnerability
reporting](https://github.com/AdilSiddiquiHQ/skillsleuth/security/advisories/new)
rather than opening a public issue.

Include:

- The version (`skillsleuth --version`) or commit.
- A minimal `SKILL.md` that should be flagged but is not.
- The rules you expected to fire.

We aim to acknowledge within 72 hours and to ship a fix or mitigation within
30 days. Reporters are credited in the release notes unless they prefer
otherwise.

## Scope

In scope:

- A malicious skill pattern that SkillSleuth fails to detect.
- A crash, hang or unbounded resource use caused by scanning a crafted skill.
- Path traversal or arbitrary file write caused by CLI arguments.
- Command execution in the scanner itself (it should never execute skill
  content).

Out of scope:

- False positives on legitimate skills (please open a normal issue, with the
  rule id).
- Vulnerabilities in the agent, model or marketplace that loads a skill.
- Anything requiring a user to run untrusted code outside SkillSleuth.

## Design guarantees

- SkillSleuth makes **no network requests**. It cannot exfiltrate what it scans.
- SkillSleuth **never executes** the content it scans.
- SkillSleuth redacts secrets in output so reports and CI logs do not leak them.
- SkillSleuth has **zero runtime dependencies**, minimising its own supply chain.
- Archive and payload handling is **bounded** (entry counts, decompressed size,
  nesting depth and per-rule match caps) so a crafted target cannot exhaust
  memory or time. A resource-exhaustion bypass is in scope: report it.

If you find behaviour that violates any of the above, treat it as a
vulnerability and report it privately.
