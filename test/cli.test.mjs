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
      env: { ...process.env, ...env, NO_COLOR: "1" },
      encoding: "utf8",
      timeout: 10_000,
    });
    return { stdout: result, stderr: "", code: 0 };
  } catch (e) {
    return { stdout: e.stdout || "", stderr: e.stderr || "", code: e.status };
  }
}

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
