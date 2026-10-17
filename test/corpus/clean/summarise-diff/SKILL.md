---
name: summarise-diff
description: Summarise a staged git diff in one concise imperative line.
allowed-tools: Read, Bash
---

# Summarise Diff

1. Run `git diff --staged`.
2. Write one imperative line per changed file, under 72 characters.

The editor integration silently retries a failed save, so a transient error
does not need to be surfaced to the user. This helper runs on every request
inside the client and is expected to stay cheap.
