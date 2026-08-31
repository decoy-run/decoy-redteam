# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.7.0] - 2026-08-31

A CLI usability pass against the [Command Line Interface Guidelines](https://clig.dev).
Attack behavior is unchanged.

### Fixed
- **Undeclared single-letter flags.** `flag()` matched `-${name[0]}` for every
  long flag, so `-n` silently meant both `--no-color` and `--no-telemetry`, `-p`
  tripped the `--pro` deprecation warning, and `-t` turned on paid team mode.
  Short forms are declared explicitly now: `-h`, `-V`, `-q`. `-l` is
  deliberately *not* an alias for `--live` — promoting a flag that previously
  did nothing to "execute attacks" is not a safe change.
- **A misspelled flag no longer changes the run silently.** Unrecognized flags
  are an error with a spelling suggestion.
- **An unknown `--category` value was ignored**, quietly running every category
  instead of the one asked for.
- **`--live` in CI failed only after probing every server.** The check for an
  answerable prompt now happens before any server is spawned.
- **Ctrl-C left spawned MCP servers behind** if it landed during a network call.

- **Local wrangler state was being published to npm.** `lib/.wrangler/` sat
  inside the `lib/` directory that the package `files` allowlist ships, so
  172 kB of miniflare cache went out with every release — including a `cf.json`
  recording the developer's colo, ASN, city and lat/long. Now gitignored and
  excluded from the tarball, which drops from 26 files to 15. `.gitignore` also
  gained `node_modules/`, `.env*` and `*.log`, which it was missing entirely.

### Added
- **`--token-file=PATH` and `DECOY_TOKEN_FILE`.** A token in `--token=` is
  visible to every process on the machine via `ps`.
- **`--no-input`** and **`--color`**.
- **Network deadlines** on every API call, including the AI-adaptive endpoints.
- **Elapsed time on the spinner**, so a long attack phase reads as working.
- **`Environment` and `Learn more` sections in `--help`**.

### Changed
- In `--json`/`--sarif` mode a fatal error now prints a JSON error object to
  stdout (`{tool, version, error, exitCode}`), so a machine consumer can tell a
  crash apart from a real finding.

**Exit codes are unchanged.** `0`/`1`/`2` mean exactly what they always have,
and usage errors and crashes still exit `1`. Ctrl-C exits `130`, as it did
before.

## [0.6.0] - 2026-06-22

New attack family: **tool poisoning** — the signature MCP attack. An MCP server
advertises each tool with a name, description, and JSON schema, and those
strings are fed to the agent's model verbatim. A malicious or compromised server
can smuggle instructions there to hijack the agent. decoy-redteam now reads the
tool surface the server *actually serves at runtime* and flags it.

This is the runtime complement to decoy-scan's static check: scan inspects what
you installed; redteam inspects what the server hands the model right now —
catching rug-pulls and servers whose served metadata differs from their
manifest.

### Added

- **`tool-poisoning` category (TPA-001…005)** — passive detection over the live
  tool surface, no payloads sent:
  - **TPA-001** instruction override (`ignore previous instructions…`) — critical
  - **TPA-002** concealment directive (`do not tell the user…`) — critical
  - **TPA-003** embedded data-exfiltration instruction (verb + external host +
    sensitive object) — critical
  - **TPA-004** fake system framing / tool-precedence priming (`<IMPORTANT>`,
    `you are now…`, `before any other tool…`) — high
  - **TPA-005** invisible-character smuggling (zero-width, bidi, Unicode Tags
    block), rendered in evidence as `‹U+XXXX›` — high
- **Runs in dry-run.** Because it sends nothing, poisoning detection works
  without `--live` and sets the exit code (2 on critical), so CI catches a
  hostile tool surface before an agent ever touches the server.
- `--json` / `--sarif` now emit passive findings in dry-run (previously these
  produced no output without `--live`).
- New exports: `detectToolPoisoning`, `POISONING_SIGNATURES`.

### Verified

- Full suite 171 tests passing (was 146) — +25 poisoning cases, including 10
  false-positive-resistance cases (`ignore case`, `do not pass secrets`, Slack
  webhooks, etc.).
- Live smoke through the CLI against a poisoned stdio server: TPA-001/002/005
  fire with `‹U+XXXX›`-rendered evidence and dry-run exits 2. The same run
  discovered four real configured MCP servers (97 tools) and produced **zero
  false positives**.

## [0.5.0] - 2026-06-22

Rebuilt server-side template injection (SSTI) detection — the thinnest
high-severity surface in the catalog (one attack, a weak oracle). SSTI has the
cleanest precision oracle available: arithmetic evaluation can't be a payload
echo.

### Added

- **INJ-017 — template injection runtime object reflection (RCE reach).**
  Reflection-only payloads (no process spawn) that ask the engine to walk its
  own object graph. A vulnerable Jinja2 returns Python class reprs
  (`<class 'object'>`); Spring SpEL returns a Java class handle
  (`class java.lang.Runtime`). Both strings are engine-emitted, never carried in
  the payload, so they prove server-side object access — the reconnaissance step
  directly before remote code execution. Critical, maps to OWASP ASI02.

### Changed

- **INJ-013 oracle rebuilt.** The old anchor was a bare `49` (from `7×7`), which
  false-fired on any tool that returned the number 49. Replaced with the
  distinctive product `1337×31337 = 41897569`: each payload carries the same
  multiplication in a different engine syntax (Jinja2/Twig, Freemarker/JSP-EL,
  ERB/EJS, Ruby interpolation, Razor), and a response containing that eight-digit
  product is unambiguous evaluation. Severity raised high → critical.
- **INJ-013 targeting widened to the real SSTI surface.** Was four tool-name
  tokens (`template|render|format|eval`); now matches email/message/report/
  notification builders and matches on tool *description* too (e.g. "renders a
  Jinja2 template"). Dropped `eval`/`expression`/`query` from the targeter so it
  no longer chases calculators and SQL tools.

### Verified

- Full suite 146 tests passing (was 134) — +9 SSTI false-positive/true-positive
  regression cases, +3 targeting cases.
- Live smoke through the engine against a real stdio MCP server: both attacks
  fire on a vulnerable render tool with captured evidence; **zero false
  positives** on a safe render tool that returned "49 messages" and echoed the
  payload verbatim (the two classic SSTI FP traps).

## [0.4.1] - 2026-05-14

Honesty + precision pass from a codebase audit. No detection-coverage
regressions — mock-server fixture still produces 7 critical + 4 high.

### Changed
- **Coverage is now `executed / planned`.** Previous versions invented a
  "Layer 2/3" denominator (estimated AI-adaptive payloads + cross-server
  chains from a string-param × encoding × pair heuristic) and shipped
  the resulting percentage in JSON/SARIF. That number was a marketing
  artifact, not a fact about the run. The upsell is now qualitative.
- **`PRV-005` (cross-tool arg smuggling) plans once per server.** Its
  signal — does the dispatcher honor meta-keys — is server-wide, so
  per-tool fan-out added KV/API cost without added signal. `CRD-001`
  and `CRD-003` deliberately still fan out per-tool: their multi-shape
  payloads (`{query}` / `{path}` / `{command}`) need to reach different
  tool shapes.

### Fixed
- **Errored baselines no longer suppress findings.** A baseline call
  that timed out has a synthetic 3s `elapsed`; using it for adaptive
  timing raised the blind-injection floor to ~10s and masked real
  signals on slow tools. `evaluateOutcome` now ignores baselines whose
  own calibration call errored.

### Removed
- **Encoding "free taste" mechanic.** `getEncodingTaste` added one
  encoded payload per server (rotated by attack-id charcode), always
  fired `noError → accepted-low`, and stamped a misleading "encoding
  bypasses defense" story title on a low-confidence acceptance. Pure
  decoration that diluted the findings list.

## [0.4.0] - 2026-05-13

This release rewrites the detection layer around exfiltration-evidence
anchors and reshapes the CLI output to be screenshot-credible. Live FP
rate across 7 real MCP servers (1,483 attacks): 0 critical, 0 high, 0
medium. Same catalog still produces 7 critical + 4 high on the
deliberately-vulnerable test fixture.

### Detection
- ~30 attack indicators rewritten from broad word matches (`/result/i`,
  `/password/i`, `/raw/i`, `/env/i`, `/html/i`, `/200/`) to structural
  exfil anchors (`^root:x:0:0:`, `AKIA[0-9A-Z]{16}`, `-----BEGIN
  PRIVATE KEY-----`, MCP cloud-metadata response shapes, real
  `id`-command output, etc.). Indicator regexes are now exported as
  named module constants for reuse across attacks.
- `evaluateOutcome` now takes the attack payload and drops indicator
  matches whose matched substring appears in the payload — kills the
  large FP class where tools echo input verbatim in errors.
- `result.isError === true` (the MCP tool-error convention) now
  short-circuits the `noError` path. Previously, tools that returned
  structured errors via the MCP envelope were misclassified as
  "accepted." Live impact on real MCPs: 49 noisy lows eliminated.

### Pipeline
- New `captureBaselines` phase runs after probe, before attack
  execution. One benign call per (server, tool) using schema-derived
  arguments (`benignArgsFor`). Per-call timeout: 3s (`BASELINE_TIMEOUT_MS`),
  configurable via `captureBaselines(..., { timeoutMs })`. Hung tools no
  longer stall the phase.
- `evaluateOutcome` now uses baseline as a comparison anchor: indicator
  matches that *also* match the baseline are suppressed (the anchor
  wasn't attack-specific behavior, it was already in normal output),
  and `timingThresholdMs` adapts to natural tool latency
  (`max(threshold, 3×baseline.elapsed + 1s)`) to dampen cold-start FPs.

### Output
- Critical and High finding cards now render the response payload in a
  boxed block between the call line and the remediation. Up to 4 lines
  wrapped at 64 chars. The proof of exploitation now appears in the
  screenshot.
- OWASP tag (`[ASI02]`, `[ASI03]`) added to every Critical/High header.
- MCP envelope unwrap: when the response is the standard
  `{content: [{type:"text", text:"…"}]}` shape, evidence shows the inner
  text instead of the JSON envelope. Affects terminal output, JSON, and
  SARIF.
- Removed the inline `[Pro]` tag and the per-finding "↳ Advanced
  AI-powered red team..." line that previously appeared inside finding
  cards. Post-summary upsell unchanged.

### Fixed
- `sendRaw` now unwraps `_mcpError` responses into the `error` field,
  matching `callTool`. Protocol attacks against servers that correctly
  reject malformed JSON-RPC no longer fire false-low findings.
- `PRT-001` (malformed JSON-RPC) had inverted indicator logic: it
  treated a proper `-32601 Method not found` rejection as "vulnerable."
  Now uses `noError: true` — vulnerable means the server *accepted* the
  malformed message.

## [0.2.1] - 2026-05-10

### Fixed
- `--no-telemetry` is now documented in `--help` output. The flag itself
  worked in 0.2.0; only the help text was missing.

## [0.3.0] - 2026-05-10

### Added
- **v2 telemetry envelope.** Same envelope upgrade as decoy-scan
  0.7.0: schema_version, event_id (dedup), run_id, env block (node,
  platform, arch, ci, host, locale). Funnel cohorting unblocked.
- **New events:** `cli.invoked`, `redteam.plan` (discovery analog).
- **Retry + persistent queue + batched drain.** Same durability
  story as decoy-scan 0.7.0.
- **First-run dashboard link** printed at end of human-mode runs.

## [0.2.3] - 2026-05-10

### Fixed
- **Telemetry now fires when no MCP configs are found.** Same bug as
  decoy-scan 0.6.2: the empty-discovery path called `process.exit(0)`
  directly without going through `exitWithCode`, so any pending
  telemetry promise was killed mid-flight. Now sends a
  `redteam_complete` event with `{noConfigs: true}` and exits through
  `exitWithCode` which awaits the pending POST.

## [0.2.0] - 2026-05-10

### Added
- **Anonymous telemetry (default-on).** Free runs now phone home a redacted
  summary of stories (severity counts, OWASP categories, attack categories —
  never the raw exploit text or tool arguments) to `/api/telemetry`.
  Identified by `~/.decoy/install_id`. Previously, free runs sent zero data
  back; the `--team` upload path was the only telemetry, which silently
  starved the dataset for the most-used path. Disable with
  `DECOY_TELEMETRY=0` env var or `--no-telemetry` flag. See
  https://decoy.run/privacy for what's collected.
- **`--no-telemetry` flag** for opting out per-run.

## [0.1.14] - 2026-05-06

### Fixed
- Star ask in 0.1.13 only printed under `--live`. Most first-time users run
  the default dry-run path, so the prompt never fired. Now also printed at
  the end of the dry-run summary.

## [0.1.13] - 2026-05-06

### Added
- Summary output now ends with a one-line GitHub star ask. Mirrors the same
  line in `decoy-tripwire` and `decoy-scan`, so users running multiple Decoy
  CLIs see consistent post-run output.

## [0.1.12] - 2026-04-28

### Added
- **Browser sign-in flow for `--team`.** When `npx decoy-redteam --team` is run
  in an interactive terminal without `--token=`, the CLI now opens
  `https://app.decoy.run/dashboard?tab=settings#s-setup` and prompts the user
  to paste their token, then persists it to `~/.decoy/token` so future
  `--team` runs don't need `--token=` again. Matches the UX of decoy-scan's
  `loginInteractive`.

### Changed
- The `Upgrade to Team` hint shown to free-tier accounts now links to
  `https://app.decoy.run/dashboard?tab=settings#s-plan` (the Plan section)
  instead of `decoy.run/pricing`.

### Privacy
- `~/.decoy/token` is **only** consulted inside the `--team` branch (paid
  feature the user explicitly opted into via the flag). Bare
  `npx decoy-redteam` runs stay purely local — they do not auto-upload
  results just because a token was saved during a previous `--team` sign-in
  or by `decoy-scan login`. Result upload still requires explicit `--token=`
  or `DECOY_TOKEN` env, matching `decoy-scan`'s `--report` opt-in model.

### Compatibility
- Non-TTY environments (CI, JSON/SARIF output) still get the original
  copy-pasteable hint — they never trigger the interactive browser flow.
