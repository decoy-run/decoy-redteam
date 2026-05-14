import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { calculateCoverage } from "../lib/coverage.mjs";

describe("calculateCoverage", () => {
  const oneServer = [{
    error: null,
    tools: [
      { name: "query", inputSchema: { properties: { sql: { type: "string" } } } },
      { name: "read", inputSchema: { properties: { path: { type: "string" } } } },
    ],
  }];

  it("reports 100% when every planned attack executed", () => {
    const coverage = calculateCoverage(oneServer, { executed: 30, planned: 30 });
    assert.strictEqual(coverage.percentage, 100);
    assert.strictEqual(coverage.executed, 30);
    assert.strictEqual(coverage.total, 30);
  });

  it("reports the actual ratio when some attacks errored out", () => {
    const coverage = calculateCoverage(oneServer, { executed: 18, planned: 30 });
    assert.strictEqual(coverage.percentage, 60);
  });

  it("reports 0% when nothing executed yet (planned but not run)", () => {
    const coverage = calculateCoverage(oneServer, { executed: 0, planned: 30 });
    assert.strictEqual(coverage.percentage, 0);
  });

  it("returns 100% for an empty plan (avoid divide-by-zero)", () => {
    const coverage = calculateCoverage([], { executed: 0, planned: 0 });
    assert.strictEqual(coverage.percentage, 100);
  });

  it("counts tools across servers; excludes errored servers from serverCount", () => {
    const servers = [
      { error: "dead", tools: [{ name: "x", inputSchema: { properties: {} } }] },
      { error: null, tools: [{ name: "a", inputSchema: { properties: {} } }, { name: "b", inputSchema: { properties: {} } }] },
      { error: null, tools: [{ name: "c", inputSchema: { properties: {} } }] },
    ];
    const coverage = calculateCoverage(servers, { executed: 10, planned: 10 });
    assert.strictEqual(coverage.serverCount, 2);
    // toolCount counts tools across ALL servers including errored, since the
    // tool list is captured pre-error. Document the choice.
    assert.strictEqual(coverage.toolCount, 4);
  });

  it("returns only honest fields — no layer1/layer2/layer3 fiction", () => {
    const coverage = calculateCoverage([], { executed: 0, planned: 0 });
    assert.ok("executed" in coverage);
    assert.ok("total" in coverage);
    assert.ok("percentage" in coverage);
    assert.ok("serverCount" in coverage);
    assert.ok("toolCount" in coverage);
    assert.strictEqual(coverage.layer1, undefined);
    assert.strictEqual(coverage.layer2, undefined);
    assert.strictEqual(coverage.layer3, undefined);
  });
});
