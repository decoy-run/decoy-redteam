<p align="center">
  <a href="https://decoy.run?utm_source=github&utm_medium=redteam_readme" target="_blank" rel="noopener noreferrer">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/decoy-run/decoy-redteam/main/.github/assets/logomark-dark.svg">
      <img src="https://raw.githubusercontent.com/decoy-run/decoy-redteam/main/.github/assets/logomark-light.svg" height="48">
    </picture>
  </a>
  <br />
</p>
<h1 align="center">
  Decoy Red Team
</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/decoy-redteam"><img alt="npm" src="https://img.shields.io/npm/v/decoy-redteam?color=111827&labelColor=111827"></a>
  <a href="https://decoy.run/docs?utm_source=github&utm_medium=redteam_readme"><img alt="documentation" src="https://img.shields.io/badge/documentation-decoy-111827?labelColor=111827"></a>
  <a href="https://decoy.run/changelog?utm_source=github&utm_medium=redteam_readme"><img alt="changelog" src="https://img.shields.io/badge/changelog-latest-111827?labelColor=111827"></a>
  <a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-MIT-111827?labelColor=111827"></a>
</p>

Autonomous red team for MCP servers. Finds exploitable vulnerabilities before attackers do. Zero dependencies. Zero setup.

**Works with:** Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline

## 🚀 Get Started

```bash
npx decoy-redteam            # Dry-run — show attack plan
npx decoy-redteam --live     # Execute attacks against your MCP servers
```

Decoy Red Team connects to every MCP server on your machine, sends adversarial payloads to their tools, and reports what's exploitable. Not a scanner — an attacker.

## 🧑‍💻 Install

No install required — run directly with `npx`. Requires Node.js 18+.

Or pin it in your CI:

```yaml
- name: Red team MCP servers
  uses: decoy-run/decoy-redteam@v1
  with:
    target: my-server
    token: ${{ secrets.DECOY_TOKEN }}
    sarif: true
```

## 🎓 Docs

- [Overview](https://decoy.run/docs/redteam/overview)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## 🗂 What it tests

**54 attack patterns** across 6 categories:

| Category | What it tests |
|----------|---------------|
| Input injection | SQL injection, command injection, path traversal, SSRF, template injection |
| Prompt injection | Instruction override, role hijack, indirect injection, encoding bypass, multi-turn |
| Credential exposure | .env files, cloud credentials, SSH keys, git tokens, shell history |
| Protocol attacks | Malformed JSON-RPC, capability escalation, replay attacks, method injection |
| Schema boundary | Type coercion, null bytes, overflow, prototype pollution, NoSQL operators |
| Privilege escalation | Scope escape, undeclared access, dotfile enumeration, argument smuggling |

Every finding maps to [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## 🛡 Safety

**Dry-run by default.** Running `npx decoy-redteam` without `--live` shows what would be tested without executing anything.

**Confirmation required.** `--live` prompts for explicit confirmation before executing. No `--yes` bypass flag.

**Safe mode default.** Live execution only runs read-only and protocol attacks. Destructive attacks require `--live --full` with an additional warning.

**Browser-automation tools are skipped in safe mode.** Tools matching `browser_*`, `navigate`, `goto`, `open_url`, `open_browser`, `open_tab`, `open_page`, `open_window`, `take_screenshot`, `screenshot`, or `screencapture` are excluded by default — otherwise SSRF URL payloads cause real browser windows to flicker open for each attack. Opt in with `--full`.

## 🛠 Usage

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

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High-risk findings |
| 2 | Critical findings |

## 🤖 Advanced AI-powered red team (paid plans)

Free `decoy-redteam` runs 54 deterministic attack patterns. The paid tiers on [Decoy Guard](https://decoy.run/pricing) (Team $29/user/mo, Business $99/user/mo) add:

- **AI-adaptive attacks** — LLM-generated payloads specific to your tool schemas
- **Encoding bypass suite** — 25+ encoding variants per injection vector
- **Cross-server chain discovery** — finds attack paths across multiple servers
- **Exportable HTML reports** — branded, print-ready security assessments
- **Continuous red teaming** — scheduled runs with drift detection

Run with `--team --token=YOUR_TOKEN`.

## 📚 Library

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

## 🚢 Release Notes

See the [hosted changelog](https://decoy.run/changelog).

## 🤝 Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

## 🔗 Related

- [decoy-scan](https://npmjs.com/package/decoy-scan) — MCP vulnerability scanner (static analysis)
- [decoy-tripwire](https://npmjs.com/package/decoy-tripwire) — Tripwire detection for AI agents
- [Decoy Guard](https://decoy.run) — Dashboard, monitoring, threat intelligence

## 📝 License

MIT — see [LICENSE](LICENSE).
