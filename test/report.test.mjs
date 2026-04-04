import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { toSarif, toJson } from "../lib/report.mjs";

const meta = { version: "0.1.0", mode: "safe", servers: 1, tools: 3 };

describe("toSarif", () => {
  it("returns valid SARIF structure with empty results", () => {
    const sarif = toSarif([], {}, meta);
    assert.strictEqual(sarif.version, "2.1.0");
    assert.strictEqual(sarif.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
    assert.strictEqual(sarif.runs.length, 1);
    assert.strictEqual(sarif.runs[0].results.length, 0);
    assert.strictEqual(sarif.runs[0].tool.driver.rules.length, 0);
    assert.strictEqual(sarif.runs[0].tool.driver.name, "decoy-redteam");
    assert.strictEqual(sarif.runs[0].tool.driver.version, "0.1.0");
  });

  it("maps mixed severities to correct SARIF levels", () => {
    const stories = [
      { attackId: "A", severity: "critical", title: "Crit", impact: "Bad", remediation: "Fix", category: "c", server: "s", tool: "t", owasp: "X", ascf: "Y" },
      { attackId: "B", severity: "high", title: "High", impact: "Bad", remediation: "Fix", category: "c", server: "s", tool: "t", owasp: "X", ascf: "Y" },
      { attackId: "C", severity: "medium", title: "Med", impact: "Ok", remediation: "Fix", category: "c", server: "s", tool: "t", owasp: "X", ascf: "Y" },
      { attackId: "D", severity: "low", title: "Low", impact: "Fine", remediation: "Fix", category: "c", server: "s", tool: "t", owasp: "X", ascf: "Y" },
    ];
    const sarif = toSarif(stories, {}, meta);

    assert.strictEqual(sarif.runs[0].results.length, 4);

    // critical and high → error
    assert.strictEqual(sarif.runs[0].results[0].level, "error");
    assert.strictEqual(sarif.runs[0].results[1].level, "error");
    // medium → warning
    assert.strictEqual(sarif.runs[0].results[2].level, "warning");
    // low → note
    assert.strictEqual(sarif.runs[0].results[3].level, "note");

    // Rules should match
    assert.strictEqual(sarif.runs[0].tool.driver.rules.length, 4);
    assert.strictEqual(sarif.runs[0].tool.driver.rules[0].id, "decoy-redteam-A");
  });

  it("encodes server name in location URI", () => {
    const stories = [
      { attackId: "A", severity: "high", title: "T", impact: "I", remediation: "R", category: "c", server: "my server", tool: "t", owasp: "X", ascf: "Y" },
    ];
    const sarif = toSarif(stories, {}, meta);
    const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.strictEqual(uri, "mcp-server://my%20server");
  });
});

describe("toJson", () => {
  it("returns correct structure with empty stories", () => {
    const json = toJson([], { executed: 0, total: 0, percentage: 100 }, meta);
    assert.ok(json.timestamp);
    assert.strictEqual(json.version, "0.1.0");
    assert.strictEqual(json.mode, "safe");
    assert.strictEqual(json.servers, 1);
    assert.strictEqual(json.tools, 3);
    assert.deepStrictEqual(json.stories, []);
    assert.deepStrictEqual(json.summary, { critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  });

  it("computes correct summary counts", () => {
    const stories = [
      { severity: "critical" },
      { severity: "critical" },
      { severity: "high" },
      { severity: "medium" },
      { severity: "low" },
      { severity: "low" },
    ];
    const json = toJson(stories, {}, meta);
    assert.strictEqual(json.summary.critical, 2);
    assert.strictEqual(json.summary.high, 1);
    assert.strictEqual(json.summary.medium, 1);
    assert.strictEqual(json.summary.low, 2);
    assert.strictEqual(json.summary.total, 6);
  });

  it("includes stories and coverage in output", () => {
    const stories = [{ severity: "high", title: "Test" }];
    const coverage = { executed: 10, total: 20, percentage: 50 };
    const json = toJson(stories, coverage, meta);
    assert.strictEqual(json.stories.length, 1);
    assert.strictEqual(json.coverage.percentage, 50);
  });
});
