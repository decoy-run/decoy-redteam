# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
