# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
