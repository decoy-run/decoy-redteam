# Security Policy

## Reporting vulnerabilities

Email security@decoy.run with details. We'll respond within 48 hours.

Do not open a public issue for security vulnerabilities.

## Scope

This tool intentionally sends adversarial payloads to MCP servers. That's its purpose. Security reports should focus on:

- Vulnerabilities in decoy-redteam itself (not in the servers it tests)
- Unintended data exfiltration from the user's machine
- Attacks that bypass the safety model (executing without `--live`, skipping confirmation)
- Token or credential leakage in output or logs

## Safety model

- Dry-run by default (no execution without `--live`)
- Interactive confirmation required for `--live`
- `--safe` mode (default) restricts to read-only attacks
- `--full` mode requires additional confirmation for destructive attacks
- API keys and tokens are never included in reports or output
