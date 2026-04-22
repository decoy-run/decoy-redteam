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

  it("matches SSRF to HTTP-client tools with a url param", () => {
    const tool = { name: "http_request", description: "Make an HTTP request", inputSchema: { properties: { url: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const ssrf = matched.filter(a => a.subcategory === "ssrf");
    assert.ok(ssrf.length >= 2, `Expected 2+ SSRF attacks, got ${ssrf.length}`);
  });

  it("matches SSRF to fetch-style tools with an endpoint param", () => {
    const tool = { name: "fetch_data", description: "Fetch", inputSchema: { properties: { endpoint: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const ssrf = matched.filter(a => a.subcategory === "ssrf");
    assert.ok(ssrf.length >= 2, `Expected 2+ SSRF attacks, got ${ssrf.length}`);
  });

  it("does not match SSRF to get_* tools with a target_id param", () => {
    const tool = { name: "get_user", description: "Fetch a user record", inputSchema: { properties: { target_id: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const ssrf = matched.filter(a => a.subcategory === "ssrf");
    assert.strictEqual(ssrf.length, 0, "SSRF should not target non-HTTP get_* tools");
  });

  it("does not match SSRF to post_* tools with a message param", () => {
    const tool = { name: "post_comment", description: "Post a comment", inputSchema: { properties: { message: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const ssrf = matched.filter(a => a.subcategory === "ssrf");
    assert.strictEqual(ssrf.length, 0, "SSRF should not target non-HTTP post_* tools");
  });

  it("does not match SQL injection to shell tools (execute_command)", () => {
    const tool = { name: "execute_command", description: "Run a shell command", inputSchema: { properties: { command: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const sqlAttacks = matched.filter(a => a.subcategory === "sql");
    assert.strictEqual(sqlAttacks.length, 0, "SQL attacks should not target shell execute_command tools");
  });

  it("does not match SQL injection to calculator tools (expression param)", () => {
    const tool = { name: "calculator", description: "Evaluate a math expression", inputSchema: { properties: { expression: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const sqlAttacks = matched.filter(a => a.subcategory === "sql");
    assert.strictEqual(sqlAttacks.length, 0, "SQL attacks should not target expression-param tools");
  });

  it("does not match command injection to run_* tools (run_migration, browser_run_code)", () => {
    for (const name of ["run_migration", "browser_run_code", "run_test"]) {
      const tool = { name, description: "Run something", inputSchema: { properties: { args: { type: "string" } } } };
      const matched = matchAttacks(tool, tool.inputSchema);
      const cmdAttacks = matched.filter(a => a.subcategory === "command");
      assert.strictEqual(cmdAttacks.length, 0, `Command injection should not target ${name}`);
    }
  });

  it("does not match command injection to tools with a code param (country_code, auth_code)", () => {
    const tool = { name: "verify_user", description: "Verify with code", inputSchema: { properties: { code: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const cmdAttacks = matched.filter(a => a.subcategory === "command");
    assert.strictEqual(cmdAttacks.length, 0, "Command injection should not target bare code-param tools");
  });

  it("still matches command injection to legitimate shell tools", () => {
    const tool = { name: "execute_command", description: "Run shell", inputSchema: { properties: { command: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const cmdAttacks = matched.filter(a => a.subcategory === "command");
    assert.ok(cmdAttacks.length >= 2, `Expected 2+ command attacks, got ${cmdAttacks.length}`);
  });

  it("does not match file attacks to tools that merely have `name` or `location` params", () => {
    const tool = { name: "create_user", description: "Create a user", inputSchema: { properties: { name: { type: "string" }, location: { type: "string" } } } };
    const matched = matchAttacks(tool, tool.inputSchema);
    const pathAttacks = matched.filter(a => a.subcategory === "path-traversal");
    assert.strictEqual(pathAttacks.length, 0, "File attacks should not target arbitrary name/location params");
  });

  it("does not match file attacks to `open_connection` or `load_balancer`", () => {
    for (const name of ["open_connection", "load_balancer", "open_session"]) {
      const tool = { name, description: "test", inputSchema: { properties: { path: { type: "string" } } } };
      const matched = matchAttacks(tool, tool.inputSchema);
      const pathAttacks = matched.filter(a => a.subcategory === "path-traversal");
      assert.strictEqual(pathAttacks.length, 0, `File attacks should not target ${name}`);
    }
  });

  it("still matches file attacks to compound file tools (cat_file, open_file, load_file)", () => {
    for (const name of ["cat_file", "open_file", "load_file", "fetch_file"]) {
      const tool = { name, description: "file op", inputSchema: { properties: { path: { type: "string" } } } };
      const matched = matchAttacks(tool, tool.inputSchema);
      const pathAttacks = matched.filter(a => a.subcategory === "path-traversal");
      assert.ok(pathAttacks.length >= 2, `Expected 2+ path-traversal for ${name}, got ${pathAttacks.length}`);
    }
  });

  it("does not match write-exfil attacks to `save_user` or `put_object`", () => {
    for (const name of ["save_user", "put_object", "save_preferences"]) {
      const tool = { name, description: "not a file op", inputSchema: { properties: { path: { type: "string" }, content: { type: "string" } } } };
      const matched = matchAttacks(tool, tool.inputSchema);
      const hadWriteAttack = matched.some(a => a.subcategory === "write-exfil");
      assert.strictEqual(hadWriteAttack, false, `write-exfil should not target ${name}`);
    }
  });

  it("still matches write-exfil to compound file-write tools (write_file, save_file, update_file)", () => {
    for (const name of ["write_file", "save_file", "update_file", "append_file"]) {
      const tool = { name, description: "file op", inputSchema: { properties: { path: { type: "string" }, content: { type: "string" } } } };
      const matched = matchAttacks(tool, tool.inputSchema);
      const hadWriteAttack = matched.some(a => a.subcategory === "write-exfil");
      assert.strictEqual(hadWriteAttack, true, `write-exfil should target ${name}`);
    }
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
