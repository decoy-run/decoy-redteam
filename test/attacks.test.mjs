import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ATTACKS, ENCODINGS, matchAttacks, getEncodingTaste } from "../lib/attacks.mjs";

describe("attack catalog", () => {
  it("has at least 50 attacks", () => {
    assert.ok(ATTACKS.length >= 50, `Expected 50+, got ${ATTACKS.length}`);
  });

  it("all attacks have required fields", () => {
    for (const a of ATTACKS) {
      assert.ok(a.id, `Missing id`);
      assert.ok(a.category, `${a.id}: missing category`);
      assert.ok(a.name, `${a.id}: missing name`);
      assert.ok(a.layer === 1, `${a.id}: only layer 1 supported`);
      assert.ok(["critical", "high", "medium", "low"].includes(a.severity), `${a.id}: invalid severity`);
      assert.ok(a.owasp, `${a.id}: missing owasp`);
      assert.ok(a.ascf, `${a.id}: missing ascf`);
      assert.ok(["read-only", "potentially-destructive", "protocol-only"].includes(a.safety), `${a.id}: invalid safety`);
      assert.ok(a.payloads?.length > 0, `${a.id}: no payloads`);
      assert.ok(a.story?.title, `${a.id}: missing story.title`);
      assert.ok(a.story?.impact, `${a.id}: missing story.impact`);
      assert.ok(a.story?.remediation, `${a.id}: missing story.remediation`);
    }
  });

  it("all attack IDs are unique", () => {
    const ids = ATTACKS.map(a => a.id);
    const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
    assert.deepStrictEqual(dupes, [], `Duplicate IDs: ${dupes.join(", ")}`);
  });

  it("covers all 6 categories", () => {
    const cats = new Set(ATTACKS.map(a => a.category));
    for (const expected of [
      "input-injection", "prompt-injection", "privilege-escalation",
      "credential-exposure", "protocol-attacks", "schema-boundary",
    ]) {
      assert.ok(cats.has(expected), `Missing category: ${expected}`);
    }
  });

  it("has protocol attacks marked as _raw", () => {
    const rawAttacks = ATTACKS.filter(a => a._raw);
    assert.ok(rawAttacks.length > 0, "No _raw protocol attacks");
    for (const a of rawAttacks) {
      assert.strictEqual(a.safety, "protocol-only", `${a.id}: _raw attack should be protocol-only`);
    }
  });
});

describe("matchAttacks", () => {
  it("matches SQL injection to query tools", () => {
    const tool = { name: "execute_query", description: "Run SQL", inputSchema: { properties: { query: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const sqlAttacks = matched.filter(a => a.subcategory === "sql");
    assert.ok(sqlAttacks.length >= 3, `Expected 3+ SQL attacks, got ${sqlAttacks.length}`);
  });

  it("matches path traversal to file tools", () => {
    const tool = { name: "read_file", description: "Read a file", inputSchema: { properties: { path: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const pathAttacks = matched.filter(a => a.subcategory === "path-traversal");
    assert.ok(pathAttacks.length >= 2, `Expected 2+ path traversal, got ${pathAttacks.length}`);
  });

  it("matches prompt injection to any tool with string params", () => {
    const tool = { name: "search", description: "Search", inputSchema: { properties: { query: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const promptAttacks = matched.filter(a => a.category === "prompt-injection");
    assert.ok(promptAttacks.length >= 5, `Expected 5+ prompt injection, got ${promptAttacks.length}`);
  });

  it("does not match command injection to file tools", () => {
    const tool = { name: "read_file", description: "Read", inputSchema: { properties: { path: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const cmdAttacks = matched.filter(a => a.subcategory === "command");
    assert.strictEqual(cmdAttacks.length, 0, "Command injection should not match file tools");
  });

  it("skips _raw protocol attacks", () => {
    const tool = { name: "anything", description: "test", inputSchema: { properties: { x: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const raw = matched.filter(a => a._raw);
    assert.strictEqual(raw.length, 0, "_raw attacks should not appear in matchAttacks");
  });
});

describe("encodings", () => {
  it("has 5 encoding transforms", () => {
    assert.strictEqual(Object.keys(ENCODINGS).length, 5);
  });

  it("homoglyph replaces characters", () => {
    const result = ENCODINGS.homoglyph("hello");
    assert.notStrictEqual(result, "hello");
    assert.strictEqual(result.length, 5);
  });

  it("base64 encodes correctly", () => {
    assert.strictEqual(ENCODINGS.base64("test"), "dGVzdA==");
  });
});

describe("getEncodingTaste", () => {
  it("returns an encoded variant", () => {
    const attack = ATTACKS.find(a => a.id === "INJ-001");
    const taste = getEncodingTaste(attack);
    assert.ok(taste, "Should return a taste");
    assert.ok(taste._isTaste);
    assert.ok(taste._encodingVariant);
    assert.ok(taste.id.endsWith("-ENC"));
  });

  it("returns null for attacks with no string payloads", () => {
    const fake = { id: "FAKE", payloads: [{ obj: true }] };
    const taste = getEncodingTaste(fake);
    assert.strictEqual(taste, null);
  });
});
