---
name: conventional-commit
description: Write a Conventional Commits message for staged changes. Use when the user asks for a commit message.
allowed-tools:
  - Read
  - Bash(git diff --staged)
---

# Conventional commit

Write a single, clear commit message for the changes the user has staged.

## When to use

Use this skill when the user asks for a commit message, or when a commit is
about to be created and no message has been given.

## Steps

1. Run `git diff --staged` to read exactly what changed.
2. Summarise the change in one imperative line, 72 characters or fewer.
3. Prefix with a type: `feat`, `fix`, `docs`, `refactor`, `test` or `chore`.
4. Add a body only when the reason for the change is not obvious.
5. Never invent changes that are not in the diff.

## Example

Input: a staged change that adds retry logic to an HTTP client.

Output:

```
feat(http): retry failed requests three times

Transient network failures were surfacing to users. Retries now
use exponential backoff with jitter.
```

## Notes

- Keep the subject line in the imperative mood ("add", not "added").
- Do not add a co-author trailer unless the user asks for one.
