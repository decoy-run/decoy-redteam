# Contributing to decoy-redteam

## Principles

- Zero dependencies. Use Node.js builtins only.
- No build step. Ship `.mjs` files directly.
- Safe by default. Dry-run unless `--live`.
- Attacks are pure data. No side effects in `lib/attacks.mjs`.

## Adding attack patterns

1. Add descriptors to the `ATTACKS` array in `lib/attacks.mjs`
2. Follow the existing format: `{ id, category, subcategory, name, layer, severity, owasp, ascf, safety, targets, payloads, indicators, story }`
3. Use unique IDs: `INJ-NNN`, `PRI-NNN`, `PRV-NNN`, `CRD-NNN`, `PRT-NNN`, `SCH-NNN`
4. Set `safety` correctly: `read-only`, `potentially-destructive`, or `protocol-only`
5. Map to OWASP Agentic Top 10 2026 (ASI01-ASI10)
6. Test against the mock server: `test/fixtures/mock-server.mjs`

## Testing

```bash
npm test              # full suite
node --test test/attacks.test.mjs   # just attacks
```

The mock server at `test/fixtures/mock-server.mjs` is deliberately vulnerable. Add response handlers for new attack types there.

## Submitting changes

- Fork, branch, PR
- All tests must pass
- One attack pattern per PR is fine — small PRs are easier to review
