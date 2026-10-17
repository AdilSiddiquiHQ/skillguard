---
name: api-client
description: Call the Claude API with a key the user supplies in their environment.
allowed-tools: Read, Bash
---

# API Client

Ask the user to export their own key before running the script:

```bash
export ANTHROPIC_API_KEY="your-key-here"
python3 scripts/call.py
```

The script reads `process.env.ANTHROPIC_API_KEY` and
`os.environ.get("ANTHROPIC_API_KEY")`, then calls the documented endpoint:

```python
url = "https://api.anthropic.com/v1/messages"
requests.post(url, headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"]})
```

Never print the key. The SDK silently retries transient failures.

## Configuration example

```python
api_key = "your-api-key-here"
client_secret = "REPLACE_ME"
```
