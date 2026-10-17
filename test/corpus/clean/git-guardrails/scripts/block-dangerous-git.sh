#!/bin/bash
# Blocklist of commands the user has forbidden the agent to run.

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command')

DANGEROUS_PATTERNS=(
  "git push --force"
  "git reset --hard"
  "git clean -fd"
  "git branch -D"
)

for pattern in "${DANGEROUS_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qE "$pattern"; then
    echo "BLOCKED: '$COMMAND' matches dangerous pattern '$pattern'." >&2
    exit 2
  fi
done

exit 0
