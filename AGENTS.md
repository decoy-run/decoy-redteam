# decoy-redteam — Agent Reference

Autonomous red team tool for MCP servers. Zero dependencies. Node.js >= 18.

## What This Tool Does

Connects to MCP servers, sends adversarial payloads to their tools, and reports exploitable vulnerabilities. Three layers of attack sophistication: deterministic (free), AI-adaptive (Guard Pro), autonomous cross-server (Guard Pro).

## Architecture

```
decoy-redteam/
├── index.mjs              — public API re-exports
├── bin/cli.mjs            — CLI entry point
├── lib/
│   ├── attacks.mjs        — 53 attack descriptors (pure data, no side effects)
│   ├── engine.mjs         — discover → probe → plan → execute → build stories
│   ├── transport.mjs      — MCP stdio connection (persistent, pooled)
│   ├── coverage.mjs       — honest coverage % calculation
│   └── report.mjs         — JSON + SARIF output
├── test/
│   ├── fixtures/mock-server.mjs  — deliberately vulnerable MCP server
│   ├── attacks.test.mjs
│   ├── engine.test.mjs
│   ├── coverage.test.mjs
│   └── cli.test.mjs
└── package.json           — zero dependencies, ES modules
```

## Attack Categories

| Category | Count | What it tests |
|----------|-------|---------------|
| input-injection | 16 | SQL, command, path traversal, SSRF, template injection |
| prompt-injection | 10 | Direct override, role hijack, indirect via output, encoding, multi-turn |
| credential-exposure | 8 | .env, cloud creds, SSH keys, shell history, error oracle |
| protocol-attacks | 7 | Malformed JSON-RPC, capability escalation, replay, method injection |
| schema-boundary | 7 | Type coercion, null bytes, overflow, extra props, NoSQL operators |
| privilege-escalation | 5 | Scope escape, undeclared access, dotfiles, argument smuggling |

## Safety Model

- Default: dry-run (shows plan, executes nothing)
- `--live`: requires interactive confirmation, read-only + protocol attacks only
- `--live --full`: includes potentially-destructive attacks, extra warning
- No `--yes` flag. Deliberate friction.
- `DECOY_REDTEAM_CONFIRM=yes` env var for CI only

## Conversion Mechanics

Three upgrade triggers built into the output:
1. **Coverage %** — "your assessment is 18% complete" (honest, per tool surface)
2. **Free taste** — one encoding bypass variant proves paid tier finds more
3. **Report cliff** — terminal output is complete, HTML export requires Guard Pro

## Key Design Decisions

- **Zero dependencies.** Node.js builtins only.
- **Connection pooling.** One process per server, reused across all attacks.
- **Stories, not findings.** Output unit is a narrative attack chain.
- **Layer 2/3 server-side.** LLM logic lives in decoy-app, not in this package. Protects the moat.
- **Safe by default.** Dry-run unless explicitly --live. No destructive attacks unless --full.

## Testing

```bash
npm test                    # full test suite (39 tests)
node --test test/cli.test.mjs   # CLI tests only
```

Mock server at `test/fixtures/mock-server.mjs` — deliberately vulnerable, used by integration tests.

## CLI Flags

| Flag | Description |
|------|-------------|
| `--live` | Execute attacks (requires confirmation) |
| `--live --full` | Include destructive attacks |
| `--target=NAME` | Target specific server |
| `--category=LIST` | Comma-separated categories |
| `--json` | JSON output to stdout |
| `--sarif` | SARIF 2.1.0 output |
| `--quiet` | Suppress status messages |
| `--no-color` | Disable colors |

## `--brief` Flag

The `--brief` flag (used with `--json`) outputs a minimal JSON summary instead of the full report. Designed for AI agents with limited context windows and CI/CD pipelines that only need pass/fail + counts.

```bash
npx decoy-redteam --live --json --brief
```

Output schema:

```json
{
  "servers": 2,        // number of connected servers
  "tools": 14,         // total tools across all servers
  "attacks": 53,       // number of attacks executed
  "critical": 1,       // findings by severity
  "high": 3,
  "medium": 5,
  "low": 2,
  "coverage": 18,      // assessment coverage percentage (0-100)
  "status": "fail"     // "pass" (no critical/high) or "fail"
}
```

All fields are always present. `status` is `"fail"` when `critical > 0 || high > 0`, otherwise `"pass"`.

## Exit Codes

- `0` — No critical or high findings
- `1` — High-risk findings
- `2` — Critical findings
