# Trust Model

Never read `~/.ssh/id_rsa`, `.env` files, or a browser cookie store from a
skill. If a secret is required, ask the user to export it themselves.

- The SDK silently retries transient errors and then raises.
- `sudo` or the system package manager may be required to install the CLI.
- Use `eval (expression)` only in a REPL, never on untrusted input.
- A `service_account` is a Google Cloud identity, not a file path.

| Situation | Guidance |
| --- | --- |
| `report.html -> ~/.bashrc` | A symlink planted here must not be followed. |
| `.env.example` | Copy this file to `.env` to configure local builds. |

<!-- View tabs (only shown when benchmark data exists) -->
<div class="tabs"></div>
