# decoy-redteam

Autonomous red team for MCP servers. Finds exploitable vulnerabilities before attackers do.

```bash
npx decoy-redteam
```

Zero dependencies. Zero setup. Works with Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, and Cline.

## What it does

Connects to every MCP server on your machine, sends adversarial payloads to their tools, and reports what's exploitable. Not a scanner — an attacker.

**53 attack patterns** across 6 categories:

| Category | What it tests |
|----------|---------------|
| Input injection | SQL injection, command injection, path traversal, SSRF, template injection |
| Prompt injection | Instruction override, role hijack, indirect injection, encoding bypass, multi-turn |
| Credential exposure | .env files, cloud credentials, SSH keys, git tokens, shell history |
| Protocol attacks | Malformed JSON-RPC, capability escalation, replay attacks, method injection |
| Schema boundary | Type coercion, null bytes, overflow, prototype pollution, NoSQL operators |
| Privilege escalation | Scope escape, undeclared access, dotfile enumeration, argument smuggling |

Every finding maps to [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Usage

```bash
# Dry-run — show attack plan without executing anything
npx decoy-redteam

# Execute attacks against your MCP servers
npx decoy-redteam --live

# Target a specific server
npx decoy-redteam --live --target=my-server

# JSON output for scripting
npx decoy-redteam --live --json

# SARIF output for GitHub Security / CI
npx decoy-redteam --live --sarif

# Only test specific categories
npx decoy-redteam --live --category=input-injection,credential-exposure
```

## Safety

**Dry-run by default.** Running `npx decoy-redteam` without `--live` shows what would be tested without executing anything.

**Confirmation required.** `--live` mode prompts for explicit confirmation before executing. No `--yes` bypass flag.

**Safe mode default.** Live execution only runs read-only and protocol attacks. Potentially destructive attacks (file writes, etc.) require `--live --full` with an additional warning.

## Output

```
  decoy-redteam v0.1.0

  1 server · 5 tools

  ── Findings ──

  ✗ CRITICAL  SQL injection — tautology accepted
    postgres → execute_query("' OR 1=1 --") → query accepted
    Impact: Attacker can bypass filters and extract all records
    Fix: Use parameterized queries
    ASCF-03 · ASI02

  ! HIGH  Path traversal — arbitrary file read via ../ sequences
    filesystem → read_file("../../.env") → credentials returned
    Impact: Read files outside intended directory
    Fix: Validate paths against an allowlist
    ASCF-04 · ASI02

  ── Coverage ──

  Tested:      142 of 340 attack patterns (42%)
  Layer 1:     142 deterministic patterns
  Layer 2:     ~198 AI-adaptive + encoding variants (paid plans)

  ── Summary ──

  3 critical · 2 high · 4 medium     142 attacks across 1 server
  decoy.run/pricing — full assessment + exportable reports
```

## CI/CD

### GitHub Action

```yaml
- name: Red team MCP servers
  uses: decoy-run/decoy-redteam@v1
```

With options:

```yaml
- name: Red team MCP servers
  uses: decoy-run/decoy-redteam@v1
  with:
    target: my-server          # Target a specific server
    category: input-injection  # Specific attack categories
    token: ${{ secrets.DECOY_TOKEN }}  # Upload to Guard dashboard
    team: true                 # AI-adaptive attacks (paid plans)
    sarif: true                # Upload to GitHub Security tab
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High-risk findings |
| 2 | Critical findings |

## Advanced AI-powered red team (paid plans)

Free `decoy-redteam` runs 53 deterministic attack patterns. The paid tiers on
[Decoy Guard](https://decoy.run/pricing) (Team $29/user/mo, Business $99/user/mo) add:

- **AI-adaptive attacks** — LLM-generated payloads specific to your tool schemas
- **Encoding bypass suite** — 25+ encoding variants per injection vector
- **Cross-server chain discovery** — finds attack paths across multiple servers
- **Exportable HTML reports** — branded, print-ready security assessments
- **Continuous red teaming** — scheduled runs with drift detection

Run with `--team --token=YOUR_TOKEN`. (`--pro` is kept as a deprecated alias.)

## Library

```javascript
import {
  discoverConfigs,
  probeServers,
  planAttacks,
  executeAttacks,
  buildStories,
  calculateCoverage,
  toSarif,
  toJson,
  ATTACKS,
  ENCODINGS,
} from 'decoy-redteam';
```

## How it works

1. **Discovers** MCP configurations across 7 supported hosts
2. **Connects** to each server via MCP stdio protocol
3. **Plans** attacks by matching patterns to tool schemas
4. **Executes** payloads against each tool (with connection pooling)
5. **Evaluates** responses for success indicators (patterns, timing, error absence)
6. **Reports** findings as attack stories with impact and remediation

## Related

- [decoy-scan](https://github.com/decoy-run/decoy-scan) — MCP vulnerability scanner (static analysis)
- [decoy-tripwire](https://github.com/decoy-run/decoy-tripwire) — Tripwire detection for AI agents
- [Decoy Guard](https://decoy.run) — Dashboard, monitoring, and threat intelligence

## License

MIT
