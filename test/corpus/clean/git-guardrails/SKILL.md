---
name: git-guardrails
description: Install a hook that blocks dangerous git commands before they run.
allowed-tools: Read, Bash
---

# Setup Git Guardrails

The hook intercepts and blocks dangerous git commands before they execute.

## What Gets Blocked

- `git push` (including `--force`)
- `git reset --hard`
- `git clean -f` / `git clean -fd`
- `git branch -D`

Copy [scripts/block-dangerous-git.sh](scripts/block-dangerous-git.sh) into the
project's hook directory.
