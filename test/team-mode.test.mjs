// Tests the --team path: billing validation, tier gating, and the silent-spinner failure mode.
// Spins a localhost HTTP server and points the CLI at it via DECOY_API_BASE.

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "bin", "cli.mjs");

// Local fake of /api/billing. Routes by token value so tests can assert specific flows.
let server;
let baseUrl;
const calls = [];

function plan(token) {
  if (token === "team-token") return { plan: "team", status: "ok", redteamUsage: { used: 2, limit: 50, remaining: 48 } };
  if (token === "business-token") return { plan: "business", status: "ok", redteamUsage: { used: 0, limit: 200, remaining: 200 } };
  if (token === "free-token") return { plan: "free", status: "ok" };
  if (token === "pro-token") return { plan: "pro", status: "ok", redteamUsage: { used: 0, limit: 50, remaining: 50 } };
  return { error: "Invalid token" };
}

before(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    calls.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), auth: req.headers.authorization || null });
    if (url.pathname === "/billing") {
      const token = url.searchParams.get("token");
      const body = plan(token);
      res.writeHead(body.error ? 401 : 200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => new Promise((r) => server.close(r)));

// The CLI reaches the billing check early then calls discoverConfigs(). We don't want it to do real
// MCP discovery during tests, so we run with a fresh HOME + no config paths. The billing check
// exits before discovery anyway in the rejected-plan path, and on accepted plans we still get
// the "Guard Team|Business" status line that we assert on.
function runCLI(args, env = {}) {
  return new Promise((resolve) => {
    const proc = spawn("node", [CLI, ...args], {
      env: {
        ...process.env,
        NO_COLOR: "1",
        DECOY_API_BASE: baseUrl,
        // Prevent the CLI from finding real MCP configs on the test host
        HOME: "/tmp/decoy-redteam-test-empty-home",
        APPDATA: "/tmp/decoy-redteam-test-empty-appdata",
        ...env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (c) => (stdout += c));
    proc.stderr.on("data", (c) => (stderr += c));
    proc.on("close", (code) => resolve({ stdout, stderr, code }));
    // Safety net for hangs
    setTimeout(() => proc.kill("SIGKILL"), 10_000);
  });
}

describe("--team billing validation (regression: auth + tier-name drift)", () => {
  it("accepts a Team-tier token and shows remaining assessments", async () => {
    const { stderr, code } = await runCLI(["--team", "--token=team-token"]);
    // CLI may exit 0 (no configs discovered) or 2 (no applicable attacks); either is fine —
    // what matters is the billing line for the Team plan.
    assert.ok(stderr.includes("Guard Team"), `expected 'Guard Team' in stderr, got: ${stderr}`);
    assert.ok(stderr.includes("48 assessments remaining"), `expected remaining count, got: ${stderr}`);
    assert.notStrictEqual(code, 1); // 1 is flag-parse error; anything else is fine
  });

  it("accepts a Business-tier token", async () => {
    const { stderr } = await runCLI(["--team", "--token=business-token"]);
    assert.ok(stderr.includes("Guard Business"), `expected 'Guard Business' in stderr, got: ${stderr}`);
    assert.ok(stderr.includes("200 assessments remaining"), `expected remaining count, got: ${stderr}`);
  });

  it("still accepts the legacy 'pro' plan for backward compatibility", async () => {
    const { stderr } = await runCLI(["--team", "--token=pro-token"]);
    // Legacy 'pro' is treated as paid and displays as 'Team'
    assert.ok(stderr.includes("Guard Team") || stderr.includes("Guard Pro"), `expected pro-as-paid, got: ${stderr}`);
  });

  it("rejects a free-tier token and exits 0 without running discovery", async () => {
    const { stderr, code } = await runCLI(["--team", "--token=free-token"]);
    assert.ok(stderr.includes("free plan"), `expected 'free plan' message, got: ${stderr}`);
    assert.ok(stderr.includes("Upgrade to Team"), `expected 'Upgrade to Team' (not 'Pro'), got: ${stderr}`);
    assert.strictEqual(code, 0);
  });

  it("sends the token as a ?token= query param (not only as Authorization header)", async () => {
    calls.length = 0;
    await runCLI(["--team", "--token=team-token"]);
    const billingCall = calls.find((c) => c.path === "/billing");
    assert.ok(billingCall, "expected a /billing request");
    assert.strictEqual(billingCall.query.token, "team-token",
      "billing endpoint only reads ?token= — sending Bearer alone causes 'Missing token parameter' rejection");
  });
});

describe("spinner in non-TTY output (regression: silent-fallback bug)", () => {
  it("writes status messages to stderr even when stdout is not a TTY", async () => {
    // Team mode runs the "Reading server source code…" and "Analyzing code + generating attacks…"
    // spinners. In the pre-fix CLI, both completions were swallowed when stderr wasn't a TTY —
    // making AI-adaptive failures invisible. We assert at least the billing status reached stderr;
    // deeper phase assertions are covered in E2E runs where real MCP servers exist.
    const { stderr } = await runCLI(["--team", "--token=team-token"]);
    assert.ok(stderr.trim().length > 0, "CLI produced no stderr output in non-TTY mode");
    assert.ok(stderr.includes("Guard Team"), "billing status missing from non-TTY stderr");
  });
});
