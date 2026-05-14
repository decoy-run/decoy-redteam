// Attack execution engine — plan, execute, observe, collect

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import { McpConnection } from "./transport.mjs";
import { ATTACKS, matchAttacks } from "./attacks.mjs";

// ─── Config Discovery (fallback when decoy-scan not available) ───

const HOST_CONFIGS = {
  "Claude Desktop": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
    return join(homedir(), ".config", "claude", "claude_desktop_config.json");
  },
  "Cursor": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    return join(homedir(), ".config", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
  },
  "Windsurf": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    return join(homedir(), ".config", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
  },
  "VS Code": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Code", "User", "settings.json");
    return join(homedir(), ".config", "Code", "User", "settings.json");
  },
  "Claude Code": () => join(homedir(), ".claude.json"),
  "Claude Code (project)": () => join(process.cwd(), ".mcp.json"),
  "Zed": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Zed", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Zed", "settings.json");
    return join(homedir(), ".config", "zed", "settings.json");
  },
  "Cline": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    if (p === "win32") return join(process.env.APPDATA || join(homedir(), "AppData", "Roaming"), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    return join(homedir(), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
  },
};

export function discoverConfigs() {
  // Try decoy-scan via dynamic import is not worth the complexity here.
  // Both tools discover configs the same way — just do it directly.

  const found = [];
  for (const [host, pathFn] of Object.entries(HOST_CONFIGS)) {
    const configPath = pathFn();
    if (existsSync(configPath)) {
      try {
        const raw = readFileSync(configPath, "utf8");
        const config = JSON.parse(raw);
        let servers = config.mcpServers || config["mcp.servers"] || {};
        if (host === "Zed" && config.context_servers) {
          servers = { ...servers, ...config.context_servers };
        }
        if (typeof servers !== "object") continue;
        found.push({ host, configPath, servers });
      } catch {
        // Config file exists but is malformed JSON — skip it
      }
    }
  }
  return found;
}

// ─── Server Probing ───

export async function probeServers(configs, { target, onStatus } = {}) {
  // Deduplicate servers across hosts
  const serverMap = new Map();
  for (const { host, servers } of configs) {
    for (const [name, entry] of Object.entries(servers)) {
      if (target && name !== target) continue;
      if (!entry.command) continue;
      if (!serverMap.has(name)) {
        serverMap.set(name, { name, entry, hosts: [host] });
      } else {
        serverMap.get(name).hosts.push(host);
      }
    }
  }

  // Parallel probe with concurrency limit of 8
  const CONCURRENCY = 8;
  const items = [...serverMap.values()];
  const results = [];

  async function pMap(items, fn, concurrency) {
    const out = [];
    let i = 0;
    async function next() {
      const idx = i++;
      if (idx >= items.length) return;
      out[idx] = await fn(items[idx]);
      await next();
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => next()));
    return out;
  }

  const probed = await pMap(items, async ({ name, entry, hosts }) => {
    onStatus?.(`Connecting to ${name}…`);
    const conn = new McpConnection(name, entry);
    try {
      const tools = await conn.connect();
      return { name, entry, hosts, conn, tools, error: null };
    } catch (e) {
      return { name, entry, hosts, conn: null, tools: [], error: e.message };
    }
  }, CONCURRENCY);

  results.push(...probed);
  return results;
}

// ─── Baseline Capture ───
//
// Before any attack runs, we call each tool once with a benign payload and
// stash the response shape. That baseline becomes the comparison anchor:
// indicator matches that *also* match the baseline aren't attack-specific
// behavior, just normal output, and get suppressed. Timing-based attacks use
// the baseline as a floor so cold-start latency doesn't masquerade as a
// blind-injection signal.

function benignArgsFor(tool) {
  const props = tool.inputSchema?.properties || {};
  const args = {};
  for (const [name, schema] of Object.entries(props)) {
    const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
    if (Array.isArray(schema.enum) && schema.enum.length > 0) {
      args[name] = schema.enum[0];
      continue;
    }
    if (type === "number" || type === "integer") args[name] = 1;
    else if (type === "boolean") args[name] = false;
    else if (type === "array") args[name] = [];
    else if (type === "object") args[name] = {};
    else args[name] = "decoy-baseline-probe";
  }
  return args;
}

// Per-call timeout for baseline probes. Tools that take >3s to answer a
// benign call are slow enough that any timing-based attack against them
// would already produce noise; we'd rather skip calibration than stall.
const BASELINE_TIMEOUT_MS = 3000;

async function callWithTimeout(conn, toolName, args, ms) {
  let timer;
  const timeout = new Promise(resolve => {
    timer = setTimeout(() => resolve({ __timedOut: true }), ms);
  });
  try {
    return await Promise.race([conn.callTool(toolName, args), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export async function captureBaselines(servers, { onProgress, timeoutMs = BASELINE_TIMEOUT_MS } = {}) {
  let done = 0;
  let total = 0;
  for (const s of servers) {
    if (s.error || !s.conn) continue;
    for (const t of s.tools) {
      if (isInteractiveSideEffectTool(t)) continue;
      total++;
    }
  }
  for (const server of servers) {
    if (server.error || !server.conn) continue;
    server.baselines = new Map();
    for (const tool of server.tools) {
      if (isInteractiveSideEffectTool(tool)) continue;
      try {
        const response = await callWithTimeout(server.conn, tool.name, benignArgsFor(tool), timeoutMs);
        if (response.__timedOut) {
          server.baselines.set(tool.name, {
            elapsed: timeoutMs, resultText: "", errorText: "baseline timeout", errored: true,
          });
        } else {
          const errored = response.error != null || response.result?.isError === true;
          server.baselines.set(tool.name, {
            elapsed: response.elapsed ?? 0,
            resultText: stringify(response.result),
            errorText: stringify(response.error),
            errored,
          });
        }
      } catch {
        server.baselines.set(tool.name, { elapsed: 0, resultText: "", errorText: "", errored: true });
      }
      done++;
      onProgress?.({ completed: done, total });
    }
  }
}

// ─── Attack Planning ───

// Tools that drive visible, out-of-band side effects — open browser windows,
// take screenshots, launch apps. Attacking them flashes real UI for each
// payload. Skipped in safe mode; --full opts back in.
export function isInteractiveSideEffectTool(tool) {
  const name = tool.name;
  // Whole Playwright-style browser_* namespace
  if (/^browser_/i.test(name)) return true;
  // Window-opening / capture tools by exact name
  return /^(navigate|goto|open_url|open_browser|open_tab|open_page|open_window|take_screenshot|screenshot|screencapture)$/i.test(name);
}

export function planAttacks(servers, { safe = true, categories } = {}) {
  const plan = [];

  // Broad attacks run once per server against one tool — the signal they
  // probe is server-wide, so per-tool fan-out adds no signal, just N× KV
  // writes / API spend / noise.
  //
  // Membership is deliberate, not structural. An earlier version gated on
  // `targets === anyString` and swept in CRD-001 / CRD-003 — but those
  // carry *multi-shape* payloads ({query}, {path}, {command}) that are
  // meant to be tried against different tool shapes. Deduping them to one
  // tool dropped real findings (e.g. CRD-001's `{path:"${HOME}/.env"}`
  // never reaching a file-read tool). Only attacks whose signal is truly
  // server-wide belong here:
  //   - prompt-injection / schema-boundary: whole categories qualify
  //   - PRV-005: dispatcher honors meta-keys regardless of target tool
  const broadCategories = new Set(["prompt-injection", "schema-boundary"]);
  const broadAttackIds = new Set(["PRV-005"]);
  const isBroadTargeting = (attack) =>
    broadCategories.has(attack.category) || broadAttackIds.has(attack.id);

  for (const server of servers) {
    if (server.error || !server.conn) continue;

    const broadPlanned = new Set(); // track attack IDs already planned for this server

    for (const tool of server.tools) {
      if (safe && isInteractiveSideEffectTool(tool)) continue;
      const attacks = matchAttacks(tool, tool.inputSchema);

      for (const attack of attacks) {
        if (safe && attack.safety === "potentially-destructive") continue;
        if (categories && !categories.includes(attack.category)) continue;

        // Broad attacks: only plan once per server
        if (isBroadTargeting(attack)) {
          if (broadPlanned.has(attack.id)) continue;
          broadPlanned.add(attack.id);
        }

        for (const payload of attack.payloads) {
          plan.push({
            server: server.name,
            tool: tool.name,
            attack,
            payload: buildArgs(tool, payload),
          });
        }
      }

    }

    // Protocol attacks: once per server, no specific tool
    const protocolAttacks = ATTACKS.filter(a => a._raw && a.layer === 1);
    for (const attack of protocolAttacks) {
      if (categories && !categories.includes(attack.category)) continue;
      for (const payload of attack.payloads) {
        plan.push({
          server: server.name,
          tool: null,
          attack,
          payload,
        });
      }
    }
  }

  // Sort: tool-call attacks first, protocol attacks last (protocol attacks can crash servers)
  plan.sort((a, b) => {
    const aRaw = a.attack._raw ? 1 : 0;
    const bRaw = b.attack._raw ? 1 : 0;
    return aRaw - bRaw;
  });

  return plan;
}

function buildArgs(tool, payload) {
  // If payload is already an object, use it directly as tool arguments
  if (typeof payload === "object" && payload !== null && !payload._replaceFirst) {
    return payload;
  }

  // If payload has _replaceFirst, inject into the first matching param
  if (typeof payload === "object" && payload._replaceFirst) {
    const props = tool.inputSchema?.properties || {};
    const firstParam = Object.keys(props)[0];
    if (firstParam) return { [firstParam]: payload.value };
    return { input: payload.value };
  }

  // String payload — inject into the best matching parameter
  const props = tool.inputSchema?.properties || {};
  const paramNames = Object.keys(props);

  // Try to match a target parameter name from the attack
  for (const name of paramNames) {
    if (/query|sql|command|path|file|url|input|text|prompt|expression|pattern/i.test(name)) {
      return { [name]: payload };
    }
  }

  // Fall back to first param, or generic "input"
  if (paramNames.length > 0) return { [paramNames[0]]: payload };
  return { input: payload };
}

// ─── Attack Execution ───

export async function executeAttacks(plan, servers, { dryRun = false, onProgress } = {}) {
  const results = [];
  const serverConns = new Map();
  for (const s of servers) {
    if (s.conn) serverConns.set(s.name, s.conn);
  }

  let completed = 0;
  for (const item of plan) {
    completed++;
    onProgress?.({ completed, total: plan.length, attack: item.attack });

    if (dryRun) {
      results.push({ ...item, outcome: "dry-run", response: null, elapsed: 0 });
      continue;
    }

    let conn = serverConns.get(item.server);
    if (!conn || !conn.connected) {
      // Try to reconnect
      const serverInfo = servers.find(s => s.name === item.server);
      if (serverInfo?.entry && !conn?.connected) {
        try {
          const newConn = new McpConnection(item.server, serverInfo.entry);
          await newConn.connect();
          serverConns.set(item.server, newConn);
          conn = newConn;
        } catch {
          results.push({ ...item, outcome: "error", response: null, elapsed: 0, error: "Reconnect failed" });
          continue;
        }
      } else {
        results.push({ ...item, outcome: "error", response: null, elapsed: 0, error: "No connection" });
        continue;
      }
    }

    try {
      let response;
      if (item.attack._raw) {
        const rawTimeout = item.attack.subcategory === "notification-abuse" ? 200 : 1000;
        response = await conn.sendRaw(
          typeof item.payload === "string" ? item.payload : JSON.stringify(item.payload),
          { timeout: rawTimeout }
        );
      } else {
        response = await conn.callTool(item.tool, item.payload);
      }

      const serverObj = servers.find(s => s.name === item.server);
      const baseline = serverObj?.baselines?.get(item.tool) || null;
      const outcome = evaluateOutcome(item.attack, response, item.payload, baseline);
      results.push({ ...item, outcome, response, elapsed: response.elapsed });
    } catch (e) {
      // Connection might have died — mark as error, will reconnect on next iteration
      if (conn) conn.close();
      results.push({ ...item, outcome: "error", response: null, elapsed: 0, error: e.message });
    }
  }

  return results;
}

export function evaluateOutcome(attack, response, payload = null, baseline = null) {
  if (!response) return "error";

  // MCP tools signal tool-level errors via `result.isError === true` (with the
  // human-readable message inside `result.content`) — distinct from JSON-RPC
  // protocol errors, which land in `response.error`. Treat them the same so a
  // tool that errors cleanly via the MCP convention isn't reported as having
  // "accepted" the payload.
  const toolErrored = response.error != null
    || (response.result && response.result.isError === true);

  // A baseline whose own call timed out / errored carries no useful signal:
  // its `elapsed` is the timeout floor (not a real latency) and its
  // result/error text is empty or synthetic ("baseline timeout"). Using
  // it for adaptive timing would mask a real blind-injection oracle on a
  // tool whose baseline just happened to be slow on the calibration pass.
  // Treat as absent.
  const effectiveBaseline = baseline?.errored ? null : baseline;

  const resultText = stringify(response.result);
  const errorText = stringify(response.error)
    + (response.result?.isError ? "\n" + stringify(response.result?.content) : "");
  const payloadText = payload == null ? "" : stringify(payload).toLowerCase();
  const ind = attack.indicators || {};

  // A pattern match counts as evidence only if (a) the matched text is not a
  // substring of the payload, and (b) the same pattern doesn't already match
  // the tool's benign baseline. (a) kills payload-echo FPs. (b) kills the
  // class where a tool's normal output happens to contain a structural anchor
  // (rare, but possible — e.g. a code-search tool whose sample response
  // includes an `-----BEGIN PRIVATE KEY-----` example). Both gates skip
  // gracefully when the input isn't supplied.
  const isExfilMatch = (pat, text) => {
    const m = text.match(pat);
    if (!m) return false;
    if (payloadText && payloadText.includes(m[0].toLowerCase())) return false;
    if (effectiveBaseline?.resultText && pat.test(effectiveBaseline.resultText)) return false;
    if (effectiveBaseline?.errorText && pat.test(effectiveBaseline.errorText)) return false;
    return true;
  };

  // Check error patterns against error text only (info disclosure via errors)
  if (ind.errorPatterns) {
    for (const pat of ind.errorPatterns) {
      if (isExfilMatch(pat, errorText)) return "vulnerable";
    }
  }

  // Check success patterns against result text only (not error messages)
  if (ind.successPatterns) {
    for (const pat of ind.successPatterns) {
      if (isExfilMatch(pat, resultText)) return "vulnerable";
    }
  }

  // Check timing — when we have a baseline, the threshold becomes the *max*
  // of the configured floor and (3× baseline + 1s). This dampens cold-start /
  // GC / connection-setup latency that previously fired blind-SQLi findings
  // on a tool's first call.
  if (ind.timingThresholdMs) {
    const adaptiveFloor = effectiveBaseline ? effectiveBaseline.elapsed * 3 + 1000 : 0;
    const threshold = Math.max(ind.timingThresholdMs, adaptiveFloor);
    if (response.elapsed >= threshold) return "vulnerable";
  }

  // No error = accepted without validation — low confidence, informational only
  if (ind.noError && !toolErrored) {
    return "accepted";
  }

  return "blocked";
}

function stringify(val) {
  if (val == null) return "";
  if (typeof val === "string") return val;
  try { return JSON.stringify(val); } catch { return String(val); }
}

// ─── Story Building ───

export function buildStories(results) {
  // Group successful attacks into stories
  const stories = [];
  const vulnerableResults = results.filter(r => r.outcome === "vulnerable" || r.outcome === "accepted");

  // Group by (server, attack.id)
  const groups = new Map();
  for (const r of vulnerableResults) {
    const key = `${r.server}:${r.attack.id}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }

  let storyIdx = 1;
  for (const [key, group] of groups) {
    const first = group[0];
    const attack = first.attack;

    // Determine confidence: "high" if any evidence has a positive indicator match,
    // "low" if the only signal is noError (accepted without pattern match)
    const hasVulnerable = group.some(r => r.outcome === "vulnerable");
    const confidence = hasVulnerable ? "high" : "low";

    // When the only indicator is noError (low confidence), cap severity at "low"
    const severity = confidence === "low" ? "low" : attack.severity;

    stories.push({
      id: `STORY-${String(storyIdx++).padStart(3, "0")}`,
      severity,
      confidence,
      category: attack.category,
      title: attack.story.title,
      impact: attack.story.impact,
      remediation: attack.story.remediation,
      owasp: attack.owasp,
      ascf: attack.ascf,
      server: first.server,
      tool: first.tool,
      attackId: attack.id,
      layer: attack.layer,
      encodingVariant: attack._encodingVariant || null,
      evidence: group.map(r => ({
        payload: summarizePayload(r.payload),
        outcome: r.outcome,
        elapsed: Math.round(r.elapsed),
        response: summarizeResponse(r.response),
      })),
    });
  }

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  stories.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  return stories;
}

function summarizePayload(payload) {
  if (typeof payload === "string") {
    return payload.length > 200 ? payload.slice(0, 200) + "…" : payload;
  }
  const s = JSON.stringify(payload);
  return s.length > 200 ? s.slice(0, 200) + "…" : s;
}

function summarizeResponse(response) {
  if (!response) return null;
  // MCP tool responses are wrapped as `{content: [{type:"text", text:"..."}]}`.
  // Unwrap to the inner text so screenshots show the leaked content directly
  // instead of the JSON envelope. Falls back to a JSON-stringified form for
  // non-MCP shapes or error responses.
  const result = response.result;
  let text;
  if (result && Array.isArray(result.content)) {
    const parts = result.content
      .map(c => (typeof c?.text === "string" ? c.text : null))
      .filter(Boolean);
    text = parts.length > 0 ? parts.join("\n") : stringify(result);
  } else {
    text = stringify(result ?? response.error);
  }
  return text.length > 300 ? text.slice(0, 300) + "…" : text;
}

// ─── Cleanup ───

export function closeAll(servers) {
  for (const s of servers) {
    s.conn?.close();
  }
}
