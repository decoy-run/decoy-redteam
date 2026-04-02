// Attack execution engine — plan, execute, observe, collect

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import { McpConnection } from "./transport.mjs";
import { ATTACKS, matchAttacks, getEncodingTaste } from "./attacks.mjs";

// ─── Config Discovery (fallback when decoy-scan not available) ───

const HOST_CONFIGS = {
  "Claude Desktop": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Claude", "claude_desktop_config.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Claude", "claude_desktop_config.json");
    return join(homedir(), ".config", "claude", "claude_desktop_config.json");
  },
  "Cursor": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
    return join(homedir(), ".config", "Cursor", "User", "globalStorage", "anysphere.cursor-mcp", "mcp.json");
  },
  "Windsurf": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
    return join(homedir(), ".config", "Windsurf", "User", "globalStorage", "codeium.windsurf-mcp", "mcp.json");
  },
  "VS Code": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Code", "User", "settings.json");
    return join(homedir(), ".config", "Code", "User", "settings.json");
  },
  "Claude Code": () => join(homedir(), ".claude", "settings.json"),
  "Claude Code (project)": () => join(process.cwd(), ".mcp.json"),
  "Zed": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Zed", "settings.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Zed", "settings.json");
    return join(homedir(), ".config", "zed", "settings.json");
  },
  "Cline": () => {
    const p = platform();
    if (p === "darwin") return join(homedir(), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
    if (p === "win32") return join(process.env.APPDATA || "", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json");
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
      } catch {}
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

  const results = [];
  for (const { name, entry, hosts } of serverMap.values()) {
    onStatus?.(`Connecting to ${name}…`);
    const conn = new McpConnection(name, entry);
    try {
      const tools = await conn.connect();
      results.push({ name, entry, hosts, conn, tools, error: null });
    } catch (e) {
      results.push({ name, entry, hosts, conn: null, tools: [], error: e.message });
    }
  }
  return results;
}

// ─── Attack Planning ───

export function planAttacks(servers, { safe = true, categories } = {}) {
  const plan = [];

  // Broad attacks (prompt injection, schema boundary) run once per server against one tool
  const broadCategories = new Set(["prompt-injection", "schema-boundary"]);

  for (const server of servers) {
    if (server.error || !server.conn) continue;

    const broadPlanned = new Set(); // track attack IDs already planned for this server
    let tasteAdded = false;

    for (const tool of server.tools) {
      const attacks = matchAttacks(tool, tool.inputSchema);

      for (const attack of attacks) {
        if (safe && attack.safety === "potentially-destructive") continue;
        if (categories && !categories.includes(attack.category)) continue;

        // Broad attacks: only plan once per server
        if (broadCategories.has(attack.category)) {
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

      // One encoding taste per server (not per tool)
      if (!tasteAdded && (!categories || categories.includes("input-injection"))) {
        const injectionAttacks = attacks.filter(a =>
          a.category === "input-injection" && (
            a.subcategory === "sql" ||
            a.subcategory === "command" ||
            a.subcategory === "path-traversal"
          )
        );
        if (injectionAttacks.length > 0) {
          const taste = getEncodingTaste(injectionAttacks[0]);
          if (taste) {
            for (const payload of taste.payloads) {
              plan.push({
                server: server.name,
                tool: tool.name,
                attack: taste,
                payload: buildArgs(tool, payload),
              });
            }
            tasteAdded = true;
          }
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

      const outcome = evaluateOutcome(item.attack, response);
      results.push({ ...item, outcome, response, elapsed: response.elapsed });
    } catch (e) {
      // Connection might have died — mark as error, will reconnect on next iteration
      if (conn) conn.close();
      results.push({ ...item, outcome: "error", response: null, elapsed: 0, error: e.message });
    }
  }

  return results;
}

function evaluateOutcome(attack, response) {
  if (!response) return "error";

  const resultText = stringify(response.result);
  const errorText = stringify(response.error);
  const ind = attack.indicators || {};

  // Check error patterns against error text only (info disclosure via errors)
  if (ind.errorPatterns) {
    for (const pat of ind.errorPatterns) {
      if (pat.test(errorText)) return "vulnerable";
    }
  }

  // Check success patterns against result text only (not error messages)
  if (ind.successPatterns) {
    for (const pat of ind.successPatterns) {
      if (pat.test(resultText)) return "vulnerable";
    }
  }

  // Check timing
  if (ind.timingThresholdMs && response.elapsed >= ind.timingThresholdMs) {
    return "vulnerable";
  }

  // No error = accepted without validation
  if (ind.noError && !response.error) {
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

    stories.push({
      id: `STORY-${String(storyIdx++).padStart(3, "0")}`,
      severity: attack.severity,
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
      isTaste: attack._isTaste || false,
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
  const text = stringify(response.result || response.error);
  return text.length > 300 ? text.slice(0, 300) + "…" : text;
}

// ─── Cleanup ───

export function closeAll(servers) {
  for (const s of servers) {
    s.conn?.close();
  }
}
