import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { planAttacks, executeAttacks, buildStories, closeAll } from "../lib/engine.mjs";
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
