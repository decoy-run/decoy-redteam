import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { calculateCoverage } from "../lib/coverage.mjs";

describe("calculateCoverage", () => {
  it("returns 100% when no Layer 2/3 applies", () => {
    // Server with no string params → no encoding variants, no chains
    const servers = [{
      error: null,
      tools: [{ name: "ping", inputSchema: { properties: { count: { type: "number" } } } }],
    }];
    const coverage = calculateCoverage(servers, 10);
    assert.ok(coverage.percentage > 50, `Expected >50%, got ${coverage.percentage}%`);
  });

  it("returns lower % with complex tool surface", () => {
    const servers = [{
      error: null,
      tools: [
        { name: "query", inputSchema: { properties: { sql: { type: "string" }, db: { type: "string" } } } },
        { name: "read", inputSchema: { properties: { path: { type: "string" } } } },
        { name: "exec", inputSchema: { properties: { cmd: { type: "string" }, args: { type: "string" } } } },
      ],
    }];
    const coverage = calculateCoverage(servers, 30);
    assert.ok(coverage.percentage < 50, `Expected <50% for complex surface, got ${coverage.percentage}%`);
    assert.ok(coverage.layer2 > 0, "Should estimate Layer 2 attacks");
  });

  it("estimates cross-server chains with 2+ servers", () => {
    const servers = [
      { error: null, tools: [{ name: "a", inputSchema: { properties: { x: { type: "string" } } } }] },
      { error: null, tools: [{ name: "b", inputSchema: { properties: { y: { type: "string" } } } }] },
    ];
    const coverage = calculateCoverage(servers, 20);
    assert.ok(coverage.layer3 > 0, "Should estimate cross-server chains");
    assert.ok(coverage.serverCount === 2);
  });

  it("skips errored servers", () => {
    const servers = [
      { error: "dead", tools: [] },
      { error: null, tools: [{ name: "a", inputSchema: { properties: { x: { type: "string" } } } }] },
    ];
    const coverage = calculateCoverage(servers, 10);
    assert.strictEqual(coverage.serverCount, 1);
  });

  it("returns correct structure", () => {
    const coverage = calculateCoverage([], 0);
    assert.ok("executed" in coverage);
    assert.ok("total" in coverage);
    assert.ok("percentage" in coverage);
    assert.ok("layer1" in coverage);
    assert.ok("layer2" in coverage);
    assert.ok("layer3" in coverage);
  });
});
