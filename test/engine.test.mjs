import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { planAttacks, executeAttacks, buildStories, captureBaselines, closeAll } from "../lib/engine.mjs";
import { McpConnection } from "../lib/transport.mjs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const MOCK_SERVER = join(__dirname, "fixtures", "mock-server.mjs");

describe("planAttacks", () => {
  it("generates attacks for vulnerable tools", () => {
    const servers = [{
      name: "test-server",
      conn: true, // truthy is enough for planning
      error: null,
      tools: [
        { name: "execute_query", description: "SQL", inputSchema: { properties: { query: { type: "string" } } } },
        { name: "read_file", description: "Read file", inputSchema: { properties: { path: { type: "string" } } } },
      ],
    }];
    const plan = planAttacks(servers, { safe: true });
    assert.ok(plan.length > 0, "Should generate attacks");

    const categories = new Set(plan.map(p => p.attack.category));
    assert.ok(categories.has("input-injection"));
    assert.ok(categories.has("prompt-injection"));
  });

  it("filters by category", () => {
    const servers = [{
      name: "test-server",
      conn: true,
      error: null,
      tools: [
        { name: "execute_query", description: "SQL", inputSchema: { properties: { query: { type: "string" } } } },
      ],
    }];
    const plan = planAttacks(servers, { categories: ["input-injection"] });
    for (const item of plan) {
      if (!item.attack._raw) {
        assert.strictEqual(item.attack.category, "input-injection", `Unexpected category: ${item.attack.category}`);
      }
    }
  });

  it("excludes destructive attacks in safe mode", () => {
    const servers = [{
      name: "test-server",
      conn: true,
      error: null,
      tools: [
        { name: "write_file", description: "Write", inputSchema: { properties: { path: { type: "string" }, content: { type: "string" } } } },
      ],
    }];
    const plan = planAttacks(servers, { safe: true });
    const destructive = plan.filter(p => p.attack.safety === "potentially-destructive");
    assert.strictEqual(destructive.length, 0, "Safe mode should exclude destructive attacks");
  });

  it("includes destructive attacks when safe=false", () => {
    const servers = [{
      name: "test-server",
      conn: true,
      error: null,
      tools: [
        { name: "write_file", description: "Write", inputSchema: { properties: { path: { type: "string" }, content: { type: "string" } } } },
      ],
    }];
    const plan = planAttacks(servers, { safe: false });
    const destructive = plan.filter(p => p.attack.safety === "potentially-destructive");
    assert.ok(destructive.length > 0, "Unsafe mode should include destructive attacks");
  });

  it("skips servers with errors", () => {
    const servers = [{
      name: "dead-server",
      conn: null,
      error: "Connection refused",
      tools: [],
    }];
    const plan = planAttacks(servers);
    assert.strictEqual(plan.length, 0);
  });

  it("skips browser automation and window-opening tools in safe mode", () => {
    const servers = [{
      name: "playwright",
      conn: true,
      error: null,
      tools: [
        { name: "browser_navigate", description: "Navigate browser", inputSchema: { properties: { url: { type: "string" } } } },
        { name: "browser_click", description: "Click", inputSchema: { properties: { selector: { type: "string" } } } },
        { name: "navigate", description: "Navigate", inputSchema: { properties: { url: { type: "string" } } } },
        { name: "take_screenshot", description: "Screenshot", inputSchema: { properties: {} } },
        { name: "open_tab", description: "Open tab", inputSchema: { properties: { url: { type: "string" } } } },
      ],
    }];
    const safe = planAttacks(servers, { safe: true });
    const toolCalls = safe.filter(p => p.tool);
    assert.strictEqual(toolCalls.length, 0, "Safe mode should skip browser automation tools");

    const full = planAttacks(servers, { safe: false });
    const fullToolCalls = full.filter(p => p.tool);
    assert.ok(fullToolCalls.length > 0, "Full mode should include browser automation tools");
  });

  it("does not skip HTTP-client tools that merely fetch URLs", () => {
    const servers = [{
      name: "api",
      conn: true,
      error: null,
      tools: [
        { name: "http_request", description: "HTTP", inputSchema: { properties: { url: { type: "string" } } } },
        { name: "fetch_data", description: "Fetch", inputSchema: { properties: { endpoint: { type: "string" } } } },
      ],
    }];
    const plan = planAttacks(servers, { safe: true });
    const ssrf = plan.filter(p => p.attack?.subcategory === "ssrf");
    assert.ok(ssrf.length > 0, "SSRF should still run against pure HTTP clients in safe mode");
  });

  it("anyString-targeted attacks fire once per server, not once per tool", () => {
    // Build a server with many string-param tools. Pre-fix, every
    // anyString-targeted attack (CRD-001, CRD-003, PRV-005) fanned out
    // 1× per tool. Post-fix, structural broad-targeting gate dedupes
    // them to fire once per server like prompt-injection already did.
    const tools = Array.from({ length: 10 }, (_, i) => ({
      name: `tool_${i}`,
      description: "Generic tool",
      inputSchema: { properties: { x: { type: "string" } } },
    }));
    const plan = planAttacks([{
      name: "wide", conn: true, error: null, tools,
    }], { safe: true });

    // Count plan entries per (attackId, category) for the three previously
    // problematic anyString attacks.
    const countsById = new Map();
    for (const p of plan) {
      countsById.set(p.attack.id, (countsById.get(p.attack.id) || 0) + 1);
    }
    // Each of these attacks has 3 payloads, so the dedup'd count should
    // be exactly 3 (one tool × 3 payloads) rather than 30 (10 × 3).
    assert.strictEqual(countsById.get("CRD-001"), 3, `CRD-001 should fire 3× total (1 tool × 3 payloads), got ${countsById.get("CRD-001")}`);
    assert.strictEqual(countsById.get("CRD-003"), 3, `CRD-003 should fire 3× total, got ${countsById.get("CRD-003")}`);
    assert.strictEqual(countsById.get("PRV-005"), 3, `PRV-005 should fire 3× total, got ${countsById.get("PRV-005")}`);
  });

  it("adds one encoding taste per server", () => {
    const servers = [{
      name: "test-server",
      conn: true,
      error: null,
      tools: [
        { name: "execute_query", description: "SQL", inputSchema: { properties: { query: { type: "string" } } } },
        { name: "read_file", description: "Read file", inputSchema: { properties: { path: { type: "string" } } } },
      ],
    }];
    const plan = planAttacks(servers, { safe: true });
    const tastes = plan.filter(p => p.attack._isTaste);
    assert.strictEqual(tastes.length, 1, `Expected 1 taste, got ${tastes.length}`);
  });
});

describe("buildStories", () => {
  it("groups findings by server and attack", () => {
    const results = [
      { server: "s1", tool: "t1", attack: { id: "INJ-001", severity: "critical", category: "input-injection", owasp: "ASI02", ascf: "ASCF-03", story: { title: "SQL injection", impact: "Bad", remediation: "Fix it" } }, outcome: "vulnerable", response: { result: "ok", elapsed: 10 }, payload: "' OR 1=1 --" },
      { server: "s1", tool: "t1", attack: { id: "INJ-001", severity: "critical", category: "input-injection", owasp: "ASI02", ascf: "ASCF-03", story: { title: "SQL injection", impact: "Bad", remediation: "Fix it" } }, outcome: "vulnerable", response: { result: "ok", elapsed: 10 }, payload: "' OR ''='" },
      { server: "s1", tool: "t1", attack: { id: "INJ-002", severity: "critical", category: "input-injection", owasp: "ASI02", ascf: "ASCF-03", story: { title: "UNION extraction", impact: "Worse", remediation: "Fix more" } }, outcome: "vulnerable", response: { result: "ok", elapsed: 10 }, payload: "' UNION..." },
    ];

    const stories = buildStories(results);
    assert.strictEqual(stories.length, 2, "Should group by attack ID");
    assert.strictEqual(stories[0].evidence.length, 2, "First story should have 2 evidence items");
  });

  it("sorts by severity", () => {
    const results = [
      { server: "s", tool: "t", attack: { id: "A", severity: "low", category: "c", owasp: "X", ascf: "Y", story: { title: "Low", impact: "i", remediation: "r" } }, outcome: "vulnerable", response: { elapsed: 1 }, payload: "x" },
      { server: "s", tool: "t", attack: { id: "B", severity: "critical", category: "c", owasp: "X", ascf: "Y", story: { title: "Crit", impact: "i", remediation: "r" } }, outcome: "vulnerable", response: { elapsed: 1 }, payload: "x" },
    ];
    const stories = buildStories(results);
    assert.strictEqual(stories[0].severity, "critical");
    assert.strictEqual(stories[1].severity, "low");
  });

  it("excludes blocked and error results", () => {
    const results = [
      { server: "s", tool: "t", attack: { id: "A", severity: "high", category: "c", owasp: "X", ascf: "Y", story: { title: "t", impact: "i", remediation: "r" } }, outcome: "blocked", response: { elapsed: 1 }, payload: "x" },
      { server: "s", tool: "t", attack: { id: "B", severity: "high", category: "c", owasp: "X", ascf: "Y", story: { title: "t", impact: "i", remediation: "r" } }, outcome: "error", response: { elapsed: 1 }, payload: "x" },
    ];
    const stories = buildStories(results);
    assert.strictEqual(stories.length, 0);
  });
});

describe("McpConnection against mock server", () => {
  let conn;

  before(async () => {
    conn = new McpConnection("mock", { command: "node", args: [MOCK_SERVER] });
    await conn.connect();
  });

  after(() => {
    conn?.close();
  });

  it("connects and lists tools", () => {
    assert.ok(conn.connected);
    assert.ok(conn.tools.length >= 5, `Expected 5+ tools, got ${conn.tools.length}`);
  });

  it("calls a tool and gets a response", async () => {
    const result = await conn.callTool("execute_query", { query: "SELECT 1" });
    assert.ok(result.result, "Should get a result");
    assert.ok(!result.error, "Should not have an error");
    assert.ok(result.elapsed > 0, "Should have timing");
  });

  it("finds SQL injection", async () => {
    const result = await conn.callTool("execute_query", { query: "' UNION SELECT table_name FROM information_schema.tables --" });
    const text = JSON.stringify(result.result);
    assert.ok(text.includes("table_name") || text.includes("users"), "Should return injected data");
  });

  it("finds path traversal", async () => {
    const result = await conn.callTool("read_file", { path: "../../.env" });
    const text = JSON.stringify(result.result);
    assert.ok(text.includes("DATABASE_URL") || text.includes("STRIPE"), "Should return .env contents");
  });

  it("finds SSRF to metadata endpoint", async () => {
    const result = await conn.callTool("http_request", { url: "http://169.254.169.254/latest/meta-data/" });
    const text = JSON.stringify(result.result);
    assert.ok(text.includes("AccessKeyId") || text.includes("Success"), "Should return cloud metadata");
  });
});

describe("full pipeline against mock server", () => {
  let servers;

  before(async () => {
    const conn = new McpConnection("mock", { command: "node", args: [MOCK_SERVER] });
    await conn.connect();
    servers = [{
      name: "mock",
      conn,
      error: null,
      tools: conn.tools,
    }];
  });

  after(() => {
    closeAll(servers);
  });

  it("planAttacks → executeAttacks → buildStories end-to-end", async () => {
    const plan = planAttacks(servers, { safe: true, categories: ["input-injection"] });
    assert.ok(plan.length > 0, "Plan should have attacks");

    const results = await executeAttacks(plan, servers);
    assert.ok(results.length > 0, "Should have results");

    const stories = buildStories(results);
    assert.ok(stories.length >= 5, `Expected at least 5 stories, got ${stories.length}`);

    const critical = stories.filter(s => s.severity === "critical");
    assert.ok(critical.length >= 1, `Expected at least 1 critical story, got ${critical.length}`);

    for (const story of stories) {
      assert.ok(story.id, "Story must have an id");
      assert.ok(story.title, "Story must have a title");
      assert.ok(story.severity, "Story must have a severity");
      assert.ok(story.evidence?.length > 0, `Story ${story.id} must have evidence`);
    }
  });
});

// ─── summarizeResponse: tested via buildStories output ────────────────────
// summarizeResponse is private; we test it through the observable side-effect
// (story.evidence[i].response shape).

describe("MCP envelope unwrap in evidence", () => {
  function story(result) {
    const results = [{
      server: "s", tool: "t",
      attack: { id: "X", severity: "high", category: "c", owasp: "ASI02", ascf: "A", story: { title: "T", impact: "I", remediation: "R" } },
      outcome: "vulnerable",
      response: { result, error: null, elapsed: 1 },
      payload: "p",
    }];
    return buildStories(results)[0];
  }

  it("unwraps MCP {content:[{type:'text',text:'…'}]} to the inner text", () => {
    const s = story({ content: [{ type: "text", text: "uid=0(root) gid=0(root)" }] });
    assert.strictEqual(s.evidence[0].response, "uid=0(root) gid=0(root)");
  });

  it("joins multiple content[] entries with newlines", () => {
    const s = story({ content: [
      { type: "text", text: "line one" },
      { type: "text", text: "line two" },
    ] });
    assert.strictEqual(s.evidence[0].response, "line one\nline two");
  });

  it("ignores non-text content[] entries", () => {
    const s = story({ content: [
      { type: "image", data: "base64xyz" },
      { type: "text", text: "the actual leak" },
    ] });
    assert.strictEqual(s.evidence[0].response, "the actual leak");
  });

  it("falls back to JSON.stringify for non-MCP shapes", () => {
    const s = story({ rows: [{ id: 1 }] });
    assert.ok(s.evidence[0].response.includes("rows"));
    assert.ok(s.evidence[0].response.includes("id"));
  });

  it("truncates responses longer than 300 chars with ellipsis", () => {
    const long = "X".repeat(500);
    const s = story({ content: [{ type: "text", text: long }] });
    assert.ok(s.evidence[0].response.length <= 301 + 1, `Expected ≤302 chars, got ${s.evidence[0].response.length}`);
    assert.ok(s.evidence[0].response.endsWith("…"));
  });

  it("short responses are returned unchanged", () => {
    const s = story({ content: [{ type: "text", text: "short" }] });
    assert.strictEqual(s.evidence[0].response, "short");
  });
});

// ─── captureBaselines: synthetic conn, no real MCP needed ──────────────────

describe("captureBaselines", () => {
  function fakeConn(handler) {
    return {
      connected: true,
      async callTool(name, args) {
        return handler(name, args);
      },
      close() {},
    };
  }

  it("calls each tool once with schema-derived benign args", async () => {
    const calls = [];
    const conn = fakeConn(async (name, args) => {
      calls.push({ name, args });
      return { result: { content: [{ type: "text", text: "ok" }] }, error: null, elapsed: 7 };
    });
    const servers = [{
      name: "s", conn, error: null,
      tools: [
        { name: "t_str", inputSchema: { properties: { q: { type: "string" } } } },
        { name: "t_num", inputSchema: { properties: { n: { type: "integer" } } } },
        { name: "t_bool", inputSchema: { properties: { flag: { type: "boolean" } } } },
        { name: "t_arr", inputSchema: { properties: { items: { type: "array" } } } },
        { name: "t_obj", inputSchema: { properties: { meta: { type: "object" } } } },
        { name: "t_enum", inputSchema: { properties: { mode: { type: "string", enum: ["read", "write"] } } } },
      ],
    }];
    await captureBaselines(servers);
    assert.strictEqual(calls.length, 6, `Expected 6 baseline calls, got ${calls.length}`);
    assert.strictEqual(calls[0].args.q, "decoy-baseline-probe");
    assert.strictEqual(calls[1].args.n, 1);
    assert.strictEqual(calls[2].args.flag, false);
    assert.deepStrictEqual(calls[3].args.items, []);
    assert.deepStrictEqual(calls[4].args.meta, {});
    assert.strictEqual(calls[5].args.mode, "read", "enum baseline uses first enum value");
  });

  it("populates server.baselines map with elapsed, resultText, errorText, errored", async () => {
    const conn = fakeConn(async () => ({
      result: { content: [{ type: "text", text: "hello" }] },
      error: null,
      elapsed: 42,
    }));
    const servers = [{
      name: "s", conn, error: null,
      tools: [{ name: "t", inputSchema: { properties: { x: { type: "string" } } } }],
    }];
    await captureBaselines(servers);
    const b = servers[0].baselines.get("t");
    assert.ok(b, "baseline entry must exist");
    assert.strictEqual(b.elapsed, 42);
    assert.ok(b.resultText.includes("hello"));
    assert.strictEqual(b.errored, false);
  });

  it("marks baseline.errored=true when callTool throws", async () => {
    const conn = fakeConn(async () => { throw new Error("boom"); });
    const servers = [{
      name: "s", conn, error: null,
      tools: [{ name: "t", inputSchema: { properties: { x: { type: "string" } } } }],
    }];
    await captureBaselines(servers);
    const b = servers[0].baselines.get("t");
    assert.ok(b);
    assert.strictEqual(b.errored, true);
  });

  it("marks baseline.errored=true when MCP returns isError:true", async () => {
    const conn = fakeConn(async () => ({
      result: { isError: true, content: [{ type: "text", text: "rejected" }] },
      error: null,
      elapsed: 3,
    }));
    const servers = [{
      name: "s", conn, error: null,
      tools: [{ name: "t", inputSchema: { properties: { x: { type: "string" } } } }],
    }];
    await captureBaselines(servers);
    assert.strictEqual(servers[0].baselines.get("t").errored, true);
  });

  it("skips browser-automation tools (same gating as planAttacks)", async () => {
    const calls = [];
    const conn = fakeConn(async (name) => { calls.push(name); return { result: {}, error: null, elapsed: 1 }; });
    const servers = [{
      name: "playwright", conn, error: null,
      tools: [
        { name: "browser_click", inputSchema: { properties: { selector: { type: "string" } } } },
        { name: "navigate", inputSchema: { properties: { url: { type: "string" } } } },
        { name: "list_pages", inputSchema: { properties: {} } },
      ],
    }];
    await captureBaselines(servers);
    assert.deepStrictEqual(calls, ["list_pages"], "Only non-side-effect tools get baseline calls");
  });

  it("skips servers with error or null conn", async () => {
    const servers = [
      { name: "broken", conn: null, error: "Connection refused", tools: [] },
    ];
    // Must not throw.
    await captureBaselines(servers);
    assert.strictEqual(servers[0].baselines, undefined, "no baselines map for unreachable servers");
  });

  it("times out a hanging baseline call rather than stalling the phase", async () => {
    let resolveHang;
    const hangPromise = new Promise(r => { resolveHang = r; });
    const conn = {
      connected: true,
      callTool: () => hangPromise,
      close() {},
    };
    const servers = [{
      name: "s", conn, error: null,
      tools: [{ name: "slow_tool", inputSchema: { properties: { x: { type: "string" } } } }],
    }];
    const t0 = Date.now();
    await captureBaselines(servers, { timeoutMs: 50 });
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 500, `Should bail in <500ms (timeoutMs=50), took ${elapsed}ms`);
    const b = servers[0].baselines.get("slow_tool");
    assert.strictEqual(b.errored, true);
    assert.strictEqual(b.errorText, "baseline timeout");
    resolveHang({ result: {}, error: null, elapsed: 0 }); // let the dangling promise resolve cleanly
  });

  it("reports progress via onProgress callback", async () => {
    const conn = fakeConn(async () => ({ result: {}, error: null, elapsed: 1 }));
    const servers = [{
      name: "s", conn, error: null,
      tools: [
        { name: "a", inputSchema: { properties: {} } },
        { name: "b", inputSchema: { properties: {} } },
        { name: "c", inputSchema: { properties: {} } },
      ],
    }];
    const progress = [];
    await captureBaselines(servers, { onProgress: p => progress.push(p) });
    assert.strictEqual(progress.length, 3);
    assert.deepStrictEqual(progress[2], { completed: 3, total: 3 });
  });
});
