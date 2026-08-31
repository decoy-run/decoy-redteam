import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = join(__dirname, "..", "bin", "cli.mjs");

function run(args = [], env = {}) {
  try {
    const result = execFileSync("node", [CLI, ...args], {
      // DECOY_TELEMETRY=0 keeps tests from posting to the live worker on every
      // CLI invocation; specific telemetry behavior is tested separately.
      env: { DECOY_TELEMETRY: "0", ...process.env, ...env, NO_COLOR: "1" },
      encoding: "utf8",
      timeout: 10_000,
    });
    return { stdout: result, stderr: "", code: 0 };
  } catch (e) {
    return { stdout: e.stdout || "", stderr: e.stderr || "", code: e.status };
  }
}

describe("flag parsing", () => {
  it("-V correctly triggers version mode", () => {
    const { stdout, code } = run(["-V"]);
    assert.strictEqual(code, 0);
    assert.match(stdout, /decoy-redteam \d+\.\d+\.\d+/);
  });

  it("--json --sarif produces an error", () => {
    const { stderr, code } = run(["--json", "--sarif"]);
    assert.strictEqual(code, 1);
    assert.ok(stderr.includes("mutually exclusive"), `Expected mutual exclusion error, got: ${stderr}`);
  });
});

describe("argument hygiene", () => {
  it("rejects an unknown flag instead of ignoring it", () => {
    const { stderr, code } = run(["--jsom"]);
    assert.strictEqual(code, 1);
    assert.ok(stderr.includes("unknown flag --jsom"), stderr);
  });

  it("suggests the intended flag", () => {
    const { stderr } = run(["--jsom"]);
    assert.ok(stderr.includes("Did you mean --json?"), stderr);
  });

  it("points a bare positional at --target", () => {
    const { stderr, code } = run(["postgres"]);
    assert.strictEqual(code, 1);
    assert.ok(stderr.includes("--target=postgres"), stderr);
  });

  it("rejects an unknown --category value", () => {
    const { stderr, code } = run(["--category=prompt-injection,bogus"]);
    assert.strictEqual(code, 1);
    assert.ok(stderr.includes('unknown category "bogus"'), stderr);
  });

  it("accepts valid --category values", () => {
    const { code } = run(["--category=prompt-injection", "--help"]);
    assert.strictEqual(code, 0);
  });

  // The old flag() derived a short alias from each long flag's first letter,
  // so -n silently meant --no-color AND --no-telemetry, and -p tripped the
  // --pro deprecation warning. Short forms are declared explicitly now.
  it("does not invent single-letter aliases", () => {
    const { stderr, code } = run(["-p"]);
    assert.strictEqual(code, 1);
    assert.ok(!stderr.includes("deprecated"), stderr);
  });

  it("keeps the declared short aliases working", () => {
    assert.strictEqual(run(["-V"]).code, 0);
    assert.strictEqual(run(["-h"]).code, 0);
  });

  it("--live refuses to prompt when stdin is not a terminal", () => {
    const { stderr, code } = run(["--live"]);
    assert.strictEqual(code, 1);
    assert.ok(stderr.includes("interactive terminal"), stderr);
  });
});

describe("CLI basics", () => {
  it("--version prints version", () => {
    const { stdout, code } = run(["--version"]);
    assert.strictEqual(code, 0);
    assert.match(stdout, /decoy-redteam \d+\.\d+\.\d+/);
  });

  it("--help prints help text", () => {
    const { stdout, code } = run(["--help"]);
    assert.strictEqual(code, 0);
    assert.ok(stdout.includes("Autonomous red team"));
    assert.ok(stdout.includes("--live"));
    assert.ok(stdout.includes("--json"));
    assert.ok(stdout.includes("--sarif"));
  });

  it("--help includes all categories", () => {
    const { stdout } = run(["--help"]);
    assert.ok(stdout.includes("input-injection"));
    assert.ok(stdout.includes("prompt-injection"));
    assert.ok(stdout.includes("protocol-attacks"));
  });

  it("--help includes exit codes", () => {
    const { stdout } = run(["--help"]);
    assert.ok(stdout.includes("0"));
    assert.ok(stdout.includes("1"));
    assert.ok(stdout.includes("2"));
  });
});

describe("CLI output modes", () => {
  it("dry-run with no servers exits cleanly", () => {
    // Use a HOME with no MCP configs and no project .mcp.json
    const { code } = run(["--target=nonexistent"], { HOME: "/tmp/decoy-test-empty" });
    assert.strictEqual(code, 0);
  });
});
