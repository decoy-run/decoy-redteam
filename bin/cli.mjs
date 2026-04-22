#!/usr/bin/env node

// decoy-redteam CLI — autonomous red team for MCP servers

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { discoverConfigs, probeServers, planAttacks, executeAttacks, buildStories, closeAll, isInteractiveSideEffectTool } from "../lib/engine.mjs";
import { calculateCoverage } from "../lib/coverage.mjs";
import { toSarif, toJson } from "../lib/report.mjs";
import { extractSource, extractGitHubSource } from "../lib/source.mjs";

// ─── Version ───

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));
const VERSION = PKG.version;

// ─── Args ───

const args = process.argv.slice(2);
const flag = (name) => args.includes(`--${name}`) || args.includes(`-${name[0]}`);
const flagVal = (name) => {
  const arg = args.find(a => a.startsWith(`--${name}=`));
  return arg ? arg.split("=").slice(1).join("=") : null;
};

const jsonMode = flag("json");
const sarifMode = flag("sarif");
const dryRun = !args.includes("--live");
const fullMode = flag("full");
const helpMode = flag("help") || flag("h");
const versionMode = args.includes("--version") || args.includes("-V");
const quietMode = flag("quiet") || flag("q");
const briefMode = flag("brief");
// --team is the primary flag; --pro is a deprecated alias kept for existing scripts.
const teamMode = flag("team") || flag("pro");
if (flag("pro") && !flag("team")) {
  process.stderr.write("[deprecated] --pro is renamed to --team. Please update your scripts.\n");
}
const targetServer = flagVal("target");
const categoryFilter = flagVal("category")?.split(",");
const tokenArg = flagVal("token") || process.env.DECOY_TOKEN;
const repoArg = flagVal("repo");

// ─── Color support ───

const isTTY = process.stderr.isTTY;
const noColor = flag("no-color") ||
  "NO_COLOR" in process.env ||
  process.env.TERM === "dumb" ||
  (!isTTY && !process.env.FORCE_COLOR);

const c = noColor
  ? { bold: "", dim: "", red: "", green: "", yellow: "", orange: "", cyan: "", magenta: "", white: "", reset: "", underline: "" }
  : {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    red: "\x1b[31m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    orange: "\x1b[38;5;208m",
    cyan: "\x1b[36m",
    magenta: "\x1b[35m",
    white: "\x1b[37m",
    reset: "\x1b[0m",
    underline: "\x1b[4m",
  };

if (jsonMode && sarifMode) {
  process.stderr.write("error: --json and --sarif are mutually exclusive\n");
  process.exit(1);
}

const SEV_COLOR = { critical: c.red, high: c.orange, medium: c.yellow, low: c.dim };
const SEV_ICON = { critical: "✗", high: "✗", medium: "~", low: " " };

// ─── Output helpers ───

function status(msg) {
  if (!quietMode && !jsonMode && !sarifMode) process.stderr.write(msg + "\n");
}

function data(msg) {
  process.stdout.write(msg + "\n");
}

// ─── Spinner ───

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

function spinner(label) {
  if (!isTTY || quietMode || jsonMode || sarifMode) return { stop() {} };
  let i = 0;
  const id = setInterval(() => {
    process.stderr.write(`\r\x1b[K  ${c.dim}${SPINNER_FRAMES[i++ % SPINNER_FRAMES.length]} ${label}${c.reset}`);
  }, 80);
  return {
    stop(msg) {
      clearInterval(id);
      process.stderr.write("\r\x1b[K");
      if (msg) status(msg);
    },
  };
}

// ─── Confirm prompt ───

async function confirm(message) {
  // CI/testing escape hatch — not a CLI flag, deliberate friction preserved
  if (process.env.DECOY_REDTEAM_CONFIRM === "yes") return true;

  if (!isTTY) {
    process.stderr.write("Error: --live requires an interactive terminal for confirmation.\n");
    process.exit(1);
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(`  ${c.yellow}${message}${c.reset} `, (answer) => {
      rl.close();
      resolve(answer.toLowerCase().startsWith("y"));
    });
  });
}

// ─── Version ───

if (versionMode) {
  data(`decoy-redteam ${VERSION}`);
  process.exit(0);
}

// ─── Help ───

if (helpMode) {
  data(`${c.bold}decoy-redteam${c.reset}
Autonomous red team for MCP servers.

${c.bold}Usage${c.reset}
  npx decoy-redteam              Dry-run — show attack plan without executing
  npx decoy-redteam --live       Execute attacks against configured MCP servers
  npx decoy-redteam --live --target=server-name   Target a specific server

${c.bold}Modes${c.reset}
  (default)        Dry-run — plan attacks, show what would be tested
  --live           Execute attacks (read-only + protocol, requires confirmation)
  --live --full    Include destructive attacks and browser-automation tools (extra warning)

${c.bold}Output${c.reset}
  --json           JSON output to stdout
  --sarif          SARIF 2.1.0 output to stdout
  --brief          Minimal JSON summary (for agents with limited context)
  --quiet, -q      Suppress status messages
  --no-color       Disable color output

${c.bold}Advanced AI-powered red team${c.reset} (Team / Business plans)
  --team               AI-adaptive attacks + source code analysis
  --team --token=TOKEN Authenticate with Decoy Guard account
  --team --repo=OWNER/REPO  Fetch source from GitHub (public or with GITHUB_TOKEN)
  --pro                Deprecated alias for --team

${c.bold}Filters${c.reset}
  --target=NAME    Only attack the named server
  --category=LIST  Comma-separated categories to test

${c.bold}Categories${c.reset}
  input-injection, prompt-injection, privilege-escalation,
  credential-exposure, protocol-attacks, schema-boundary

${c.bold}Examples${c.reset}
  npx decoy-redteam                           Show attack plan (dry-run)
  npx decoy-redteam --live                    Execute attacks (requires confirmation)
  npx decoy-redteam --live --target=postgres  Target one server
  npx decoy-redteam --live --json             Machine-readable results
  npx decoy-redteam --live --json | jq '.summary'   Just the summary
  npx decoy-redteam --live --sarif > rt.sarif SARIF for GitHub Security tab
  npx decoy-redteam --team --token=xxx        AI-adaptive attacks (paid plans)
  DECOY_REDTEAM_CONFIRM=yes npx decoy-redteam --live --json   CI/CD usage

${c.bold}Exit codes${c.reset}
  0  No critical or high findings
  1  High-risk findings
  2  Critical findings

${c.bold}Agent integration${c.reset}
  This CLI ships with AGENTS.md for AI agent reference.
  Use --json for structured output. Use --brief for minimal summaries.
  Set DECOY_REDTEAM_CONFIRM=yes to skip confirmation in CI/CD.

${c.dim}https://decoy.run${c.reset}`);
  process.exit(0);
}

// ─── Pro attack helpers ───

function parseIndicators(ind) {
  if (!ind) return { noError: true };
  const parsed = { noError: ind.noError ?? true };
  if (ind.successPatterns) {
    parsed.successPatterns = ind.successPatterns
      .map(p => { try { return new RegExp(p, "i"); } catch { return null; } })
      .filter(Boolean);
  }
  if (ind.errorPatterns) {
    parsed.errorPatterns = ind.errorPatterns
      .map(p => { try { return new RegExp(p, "i"); } catch { return null; } })
      .filter(Boolean);
  }
  return parsed;
}

// ─── Guard Upload ───

async function uploadResults(stories, coverage, servers, token) {
  const payload = {
    tool: "decoy-redteam",
    version: VERSION,
    timestamp: new Date().toISOString(),
    servers: servers.map(s => ({ name: s.name, tools: s.tools?.length || 0 })),
    stories: stories.map(s => ({
      id: s.id, severity: s.severity, title: s.title,
      category: s.category, server: s.server, tool: s.tool,
      attackId: s.attackId, owasp: s.owasp, ascf: s.ascf,
    })),
    coverage,
    summary: {
      critical: stories.filter(s => s.severity === "critical").length,
      high: stories.filter(s => s.severity === "high").length,
      medium: stories.filter(s => s.severity === "medium").length,
      low: stories.filter(s => s.severity === "low").length,
      total: stories.length,
    },
  };

  try {
    const res = await fetch(`https://app.decoy.run/api/redteam/upload`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      status(`  ${c.green}✓${c.reset} Results saved to Guard  ${c.dim}app.decoy.run/dashboard${c.reset}\n`);
    } else {
      const body = await res.json().catch(() => ({}));
      if (res.status === 403) {
        status(`  ${c.dim}↳ Upload requires Advanced AI-powered red team  decoy.run/pricing${c.reset}\n`);
      } else {
        status(`  ${c.yellow}!${c.reset} ${c.dim}Upload failed: ${body.error || res.status}${c.reset}\n`);
      }
    }
  } catch {
    // Network error — don't block the report, just skip silently
  }
}

// ─── Main ───

async function main() {
  // SIGINT handler — clean up spawned processes
  const servers = [];
  const cleanup = () => { closeAll(servers); process.exit(130); };
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  status(`\n  ${c.bold}decoy-redteam${c.reset} ${c.dim}v${VERSION}${c.reset}\n`);

  // Authorization warning — required for a red team tool
  if (process.env.DECOY_REDTEAM_AUTHORIZED !== "1") {
    if (dryRun) {
      status(`  ${c.yellow}⚠️${c.reset} decoy-redteam tests ${c.bold}YOUR OWN${c.reset} MCP servers for vulnerabilities.`);
      status(`     Only run against servers you own or have explicit authorization to test.`);
      status(`     By proceeding, you confirm you have authorization for this security test.\n`);
    }
    // In --live mode, the warning is shown as part of the confirmation prompt below
  }

  // Pro mode
  if (teamMode) {
    if (tokenArg) {
      // Validate token against Guard API
      try {
        const res = await fetch(`https://app.decoy.run/api/billing`, {
          headers: { "Authorization": `Bearer ${tokenArg}` },
        });
        const billing = await res.json();
        if (billing.plan === "pro" || billing.plan === "business") {
          const usage = billing.redteamUsage || {};
          const remaining = (usage.limit || 20) - (usage.used || 0);
          status(`  ${c.green}✓${c.reset} Guard ${billing.plan === "business" ? "Business" : "Pro"}  ${c.dim}${remaining} assessments remaining this month${c.reset}\n`);
        } else {
          status(`  ${c.yellow}Your account is on the ${billing.plan || "free"} plan.${c.reset}`);
          status(`  Upgrade to Pro for AI-adaptive attacks and exportable reports.\n`);
          status(`  ${c.cyan}decoy.run/pricing${c.reset}\n`);
          process.exit(0);
        }
      } catch {
        status(`  ${c.red}Could not verify account.${c.reset} Check your token and try again.\n`);
        process.exit(1);
      }
    } else {
      status(`  ${c.bold}Advanced AI-powered red team${c.reset} — adaptive attacks, cross-server chains, exportable reports\n`);
      status(`  Available on Decoy Guard paid plans. Sign up and pass your token:\n`);
      status(`  ${c.cyan}npx decoy-redteam --team --token=YOUR_TOKEN${c.reset}\n`);
      status(`  Don't have an account? Get started at ${c.underline}decoy.run/pricing${c.reset}\n`);
      process.exit(0);
    }
  }

  // Discover configs
  const configs = discoverConfigs();
  if (configs.length === 0) {
    if (jsonMode) {
      const empty = { timestamp: new Date().toISOString(), version: VERSION, stories: [], coverage: { executed: 0, total: 0, percentage: 100 }, summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 } };
      await new Promise(r => process.stdout.write(JSON.stringify(empty, null, 2) + "\n", r));
    } else if (sarifMode) {
      const empty = { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "decoy-redteam", version: VERSION, rules: [] } }, results: [] }] };
      await new Promise(r => process.stdout.write(JSON.stringify(empty, null, 2) + "\n", r));
    } else {
      status(`  No MCP configurations found.\n  Checked: Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline\n\n  Hint: Create .mcp.json in your project or configure an MCP client. See https://decoy.run/docs`);
    }
    process.exit(0);
  }

  const hosts = configs.map(cfg => cfg.host);
  const totalServers = new Set(configs.flatMap(c => Object.keys(c.servers))).size;
  status(`  ${c.dim}Hosts:${c.reset} ${hosts.join(", ")}`);
  status(`  ${c.dim}Servers:${c.reset} ${totalServers}${targetServer ? ` (targeting: ${targetServer})` : ""}\n`);

  // Connect to servers
  const sp = spinner("Connecting…");
  const probed = await probeServers(configs, { target: targetServer });
  servers.push(...probed);
  sp.stop();

  const connected = probed.filter(s => s.conn);
  const failed = probed.filter(s => s.error);

  // Show connection results per server
  for (const s of connected) {
    status(`  ${c.green}✓${c.reset} ${c.bold}${s.name}${c.reset}  ${c.dim}${s.tools.length} tools${c.reset}`);
  }
  for (const f of failed) {
    status(`  ${c.red}✗${c.reset} ${c.bold}${f.name}${c.reset}  ${c.dim}${f.error}${c.reset}`);
  }

  if (connected.length === 0) {
    status(`\n  No servers responded.\n  Hint: Check that the server command is correct and the binary is installed\n`);
    closeAll(servers);
    process.exit(0);
  }

  const toolCount = connected.reduce((sum, s) => sum + s.tools.length, 0);
  status("");

  // Plan attacks
  const safe = !fullMode;
  const plan = planAttacks(connected, { safe, categories: categoryFilter });

  // Count tools that planAttacks skipped in safe mode so we can disclose them
  const skippedSideEffect = safe
    ? connected.flatMap(s => s.tools.filter(isInteractiveSideEffectTool)).length
    : 0;

  // Pro: extract source code + fetch AI-adaptive attacks
  let proPlan = [];
  if (teamMode && tokenArg) {
    // Extract source code — local (node_modules) and/or GitHub
    const sp3a = spinner(repoArg ? "Fetching source from GitHub…" : "Reading server source code…");

    const serverSchemas = connected.map(s => {
      const source = extractSource(s.entry);
      const schema = {
        name: s.name,
        tools: s.tools.map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      };
      if (source && source.files.length > 0) {
        schema.source = source.files.map(f => ({ path: f.path, content: f.content }));
        schema.sourceLines = source.totalLines;
      }
      return schema;
    });

    // GitHub source (--repo flag) — adds to the first server's source
    if (repoArg) {
      try {
        const ghToken = process.env.GITHUB_TOKEN;
        const ghSource = await extractGitHubSource(repoArg, { token: ghToken });
        if (ghSource && ghSource.files.length > 0) {
          // Attach to the first server (or the targeted one)
          const target = serverSchemas[0];
          if (target) {
            target.source = [...(target.source || []), ...ghSource.files.map(f => ({ path: `github:${f.path}`, content: f.content }))];
            target.sourceLines = (target.sourceLines || 0) + ghSource.totalLines;
          }
        }
      } catch (e) {
        sp3a.stop(`  ${c.yellow}!${c.reset} ${c.dim}GitHub: ${e.message}${c.reset}\n`);
      }
    }

    const totalSourceLines = serverSchemas.reduce((s, srv) => s + (srv.sourceLines || 0), 0);
    if (totalSourceLines > 0) {
      const sourceLabel = repoArg ? "source code (local + GitHub)" : "server source code";
      sp3a.stop(`  ${c.green}✓${c.reset} ${totalSourceLines} lines of ${sourceLabel} extracted\n`);
    } else {
      sp3a.stop(`  ${c.dim}No readable source found (servers may be compiled/remote)${c.reset}\n`);
    }

    const sp3 = spinner("Analyzing code + generating attacks…");
    try {
      const res = await fetch(`https://app.decoy.run/api/redteam/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${tokenArg}` },
        body: JSON.stringify({ servers: serverSchemas }),
      });
      if (res.ok) {
        const data = await res.json();
        proPlan = (data.attacks || []).map(a => {
          // Convert Pro attacks into plan items that the engine can execute
          const serverName = a.tool ? connected.find(s => s.tools.some(t => t.name === a.tool))?.name : connected[0]?.name;
          return {
            server: serverName || connected[0]?.name,
            tool: a.tool,
            attack: {
              id: a.id,
              category: a.category || "ai-adaptive",
              name: a.name || a.story?.title || "AI-generated attack",
              layer: 2,
              severity: a.severity || "high",
              owasp: a.owasp || "ASI01",
              ascf: a.ascf || "ASCF-PRO",
              safety: "read-only",
              indicators: parseIndicators(a.indicators),
              story: a.story || { title: a.name || "AI-identified vulnerability", impact: a.reasoning || "Potential vulnerability identified by AI analysis", remediation: a.story?.remediation || "Review and remediate" },
              _pro: true,
            },
            payload: a.payloads?.[0] || {},
          };
        }).filter(p => p.tool); // Drop attacks without a valid tool name
        sp3.stop(`  ${c.green}✓${c.reset} ${proPlan.length} AI-adaptive attacks generated\n`);
      } else {
        const err = await res.json().catch(() => ({}));
        sp3.stop(`  ${c.yellow}!${c.reset} ${c.dim}Pro plan: ${err.error || res.status}${c.reset}\n`);
      }
    } catch (e) {
      sp3.stop(`  ${c.yellow}!${c.reset} ${c.dim}Pro plan unavailable: ${e.message}${c.reset}\n`);
    }
  }

  if (plan.length === 0) {
    status("  No applicable attacks for the discovered tools.\n  Hint: The discovered tools don't match any attack patterns. Try --category to see available categories\n");
    closeAll(servers);
    process.exit(0);
  }

  // Dry-run mode: show plan and exit
  if (dryRun) {
    const byCat = {};
    for (const item of plan) {
      const cat = item.attack.category;
      byCat[cat] = (byCat[cat] || 0) + 1;
    }

    status(`  ${c.dim}── Attack Plan ──${c.reset}\n`);
    const catNames = {
      "input-injection": "Input injection",
      "prompt-injection": "Prompt injection",
      "credential-exposure": "Credential exposure",
      "privilege-escalation": "Privilege escalation",
      "protocol-attacks": "Protocol attacks",
      "schema-boundary": "Schema boundary",
    };
    for (const [cat, count] of Object.entries(byCat)) {
      status(`  ${c.dim}·${c.reset} ${catNames[cat] || cat}  ${c.dim}${count} patterns${c.reset}`);
    }
    status(`\n  ${c.bold}${plan.length} attacks${c.reset} ready against ${connected.length} server${connected.length > 1 ? "s" : ""}`);

    if (skippedSideEffect > 0) {
      status(`  ${c.dim}Skipped ${skippedSideEffect} browser/window tool${skippedSideEffect > 1 ? "s" : ""} — use --full to include${c.reset}`);
    }

    const coverage = calculateCoverage(connected, plan.length);
    status(`  ${c.dim}Assessment coverage:${c.reset} ${c.bold}${coverage.percentage}%${c.reset}`);

    const untested = coverage.total - coverage.executed;
    if (untested > 0 && coverage.percentage < 90) {
      status(`  ${c.dim}Advanced AI-powered red team would add ~${untested} AI-adaptive patterns  decoy.run/pricing${c.reset}`);
    }

    status(`\n  ${c.cyan}npx decoy-redteam --live${c.reset}                Execute attacks`);
    status(`  ${c.cyan}npx decoy-redteam --live --target=NAME${c.reset}  Target one server\n`);

    closeAll(servers);
    process.exit(0);
  }

  // Live mode: confirm before executing
  const safetyLabel = safe ? "read-only + protocol" : "FULL (includes destructive)";
  status(`  ${c.dim}── Live Mode ──${c.reset}\n`);
  status(`  Targets: ${connected.map(s => s.name).join(", ")}`);
  status(`  Attacks: ${plan.length}`);
  status(`  Safety:  ${safe ? safetyLabel : `${c.red}${safetyLabel}${c.reset}`}`);
  if (skippedSideEffect > 0) {
    status(`  ${c.dim}Skipped ${skippedSideEffect} browser/window tool${skippedSideEffect > 1 ? "s" : ""} — use --full to include${c.reset}`);
  }
  status("");

  if (!safe) {
    status(`  ${c.red}Warning: --full includes potentially destructive attacks.${c.reset}`);
    status(`  ${c.red}These may write files, execute commands, or modify data.${c.reset}`);
    status(`  ${c.red}Browser-automation tools (browser_*, navigate) will also be attacked,${c.reset}`);
    status(`  ${c.red}which can briefly open real windows for each URL payload.${c.reset}\n`);
  }

  if (process.env.DECOY_REDTEAM_AUTHORIZED !== "1") {
    status(`  ${c.yellow}⚠️${c.reset} decoy-redteam tests ${c.bold}YOUR OWN${c.reset} MCP servers for vulnerabilities.`);
    status(`     Only run against servers you own or have explicit authorization to test.`);
    status(`     By proceeding, you confirm you have authorization for this security test.\n`);
  }

  const proceed = await confirm("Execute attacks? (yes/no)");
  if (!proceed) {
    status("\n  Aborted.\n");
    closeAll(servers);
    process.exit(0);
  }
  status("");

  // Merge Pro attacks into plan
  const fullPlan = [...plan, ...proPlan];

  // Execute Phase 1
  let lastUpdate = 0;
  let frameIdx = 0;
  const interactive = isTTY && !quietMode && !jsonMode && !sarifMode;
  const startTime = performance.now();
  const phaseLabel = teamMode ? "Phase 1 — deterministic" + (proPlan.length > 0 ? " + AI-adaptive" : "") : "Attacking";
  if (interactive) {
    process.stderr.write(`\r\x1b[K  ${c.dim}${SPINNER_FRAMES[0]} ${phaseLabel}…${c.reset}`);
  }
  const results = await executeAttacks(fullPlan, connected, {
    dryRun: false,
    onProgress: ({ completed, total, attack }) => {
      if (!interactive) return;
      const now = Date.now();
      if (now - lastUpdate > 150) {
        const cat = attack.category.replace(/-/g, " ");
        const pct = Math.round((completed / total) * 100);
        const frame = SPINNER_FRAMES[frameIdx++ % SPINNER_FRAMES.length];
        process.stderr.write(`\r\x1b[K  ${c.dim}${frame} ${phaseLabel} · ${pct}% · ${cat}${c.reset}`);
        lastUpdate = now;
      }
    },
  });
  if (interactive) process.stderr.write("\r\x1b[K");
  const p1Elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
  status(`  ${c.dim}${results.length} attacks executed in ${p1Elapsed}s${c.reset}\n`);

  // Phase 2 — Iterate: send results to API, get refined attacks, execute
  let iterateResults = [];
  if (teamMode && tokenArg && proPlan.length > 0) {
    const sp4 = spinner("Phase 2 — analyzing results, generating refined attacks…");
    try {
      // Summarize results for the API
      const resultSummary = results.map(r => ({
        tool: r.tool,
        server: r.server,
        attackId: r.attack?.id,
        category: r.attack?.category,
        name: r.attack?.name,
        outcome: r.outcome,
        response: r.response?.result ? JSON.stringify(r.response.result).slice(0, 200) : r.response?.error?.toString().slice(0, 200) || null,
      }));

      const serverSchemas = connected.map(s => ({
        name: s.name,
        tools: s.tools.map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      }));

      const iterRes = await fetch(`https://app.decoy.run/api/redteam/iterate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${tokenArg}` },
        body: JSON.stringify({ servers: serverSchemas, results: resultSummary }),
      });

      if (iterRes.ok) {
        const iterData = await iterRes.json();
        const refinedPlan = (iterData.attacks || []).map(a => {
          const serverName = a.tool ? connected.find(s => s.tools.some(t => t.name === a.tool))?.name : connected[0]?.name;
          return {
            server: serverName || connected[0]?.name,
            tool: a.tool,
            attack: {
              id: a.id,
              category: a.category || "refined",
              name: a.name || a.story?.title || "AI-generated attack",
              layer: 3,
              severity: a.severity || "high",
              owasp: a.owasp || "ASI01",
              ascf: a.ascf || "ASCF-PRO",
              safety: "read-only",
              indicators: parseIndicators(a.indicators),
              story: a.story || { title: a.name || "AI-identified vulnerability", impact: a.reasoning || "Potential vulnerability identified by AI analysis", remediation: a.story?.remediation || "Review and remediate" },
              _pro: true,
              _refined: true,
            },
            payload: a.payloads?.[0] || {},
          };
        }).filter(p => p.tool);

        if (refinedPlan.length > 0) {
          sp4.stop(`  ${c.green}✓${c.reset} ${refinedPlan.length} refined attacks generated\n`);

          if (interactive) {
            process.stderr.write(`\r\x1b[K  ${c.dim}${SPINNER_FRAMES[0]} Phase 2 — executing refined attacks…${c.reset}`);
          }
          iterateResults = await executeAttacks(refinedPlan, connected, {
            dryRun: false,
            onProgress: ({ completed, total, attack }) => {
              if (!interactive) return;
              const now = Date.now();
              if (now - lastUpdate > 150) {
                const frame = SPINNER_FRAMES[frameIdx++ % SPINNER_FRAMES.length];
                process.stderr.write(`\r\x1b[K  ${c.dim}${frame} Phase 2 · refining · ${completed}/${total}${c.reset}`);
                lastUpdate = now;
              }
            },
          });
          if (interactive) process.stderr.write("\r\x1b[K");
          const p2Elapsed = ((performance.now() - startTime) / 1000 - parseFloat(p1Elapsed)).toFixed(1);
          status(`  ${c.dim}${iterateResults.length} refined attacks executed in ${p2Elapsed}s${c.reset}\n`);
        } else {
          sp4.stop(`  ${c.dim}No additional attacks to refine${c.reset}\n`);
        }
      } else {
        sp4.stop(`  ${c.dim}Iteration skipped${c.reset}\n`);
      }
    } catch {
      sp4.stop(`  ${c.dim}Iteration unavailable${c.reset}\n`);
    }
  }

  // Combine all results
  const allResults = [...results, ...iterateResults];
  const totalElapsed = ((performance.now() - startTime) / 1000).toFixed(1);
  if (iterateResults.length > 0) {
    status(`  ${c.dim}Total: ${allResults.length} attacks in ${totalElapsed}s${c.reset}\n`);
  }

  // Build stories from all results
  const stories = buildStories(allResults);

  // Coverage: count Layer 1 deterministic attacks only for the denominator calculation
  // Pro attacks are ADDITIONAL — they don't reduce the "what's left" estimate
  const l1Results = results.filter(r => r.outcome !== "error");
  const proResults = iterateResults.filter(r => r.outcome !== "error");
  const coverage = calculateCoverage(connected, l1Results.length);
  // If Pro ran, adjust the display to show total executed including Pro
  if (proResults.length > 0) {
    coverage.executed += proResults.length;
    coverage.total += proResults.length;
    coverage.percentage = Math.round((coverage.executed / coverage.total) * 100);
  }

  // Upload to Guard (any mode — if token provided, save results)
  if (tokenArg) {
    await uploadResults(stories, coverage, connected, tokenArg);
  }

  // Output
  if (jsonMode && briefMode) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const s of stories) counts[s.severity] = (counts[s.severity] || 0) + 1;
    const brief = {
      servers: connected.length,
      tools: toolCount,
      attacks: allResults.length,
      critical: counts.critical,
      high: counts.high,
      medium: counts.medium,
      low: counts.low,
      coverage: coverage.percentage,
      status: counts.critical > 0 || counts.high > 0 ? "fail" : "pass",
    };
    closeAll(servers);
    await new Promise(r => process.stdout.write(JSON.stringify(brief) + "\n", r));
    exitWithCode(stories);
    return;
  }

  if (jsonMode) {
    const meta = { version: VERSION, mode: safe ? "safe" : "full", servers: connected.length, tools: toolCount };
    const json = JSON.stringify(toJson(stories, coverage, meta), null, 2);
    closeAll(servers);
    await new Promise(r => process.stdout.write(json + "\n", r));
    exitWithCode(stories);
    return;
  }

  if (sarifMode) {
    const meta = { version: VERSION };
    const json = JSON.stringify(toSarif(stories, coverage, meta), null, 2);
    closeAll(servers);
    await new Promise(r => process.stdout.write(json + "\n", r));
    exitWithCode(stories);
    return;
  }

  // Terminal output
  printStories(stories);
  printSummary(stories, results, connected, coverage);

  closeAll(servers);
  exitWithCode(stories);
}

// ─── Terminal output ───

function printStories(stories) {
  if (stories.length === 0) {
    status(`  ${c.green}✓${c.reset} ${c.bold}Clean.${c.reset} No exploitable vulnerabilities found.\n`);
    return;
  }

  // Group by severity for visual scanning
  const critical = stories.filter(s => s.severity === "critical");
  const high = stories.filter(s => s.severity === "high");
  const medium = stories.filter(s => s.severity === "medium");
  const low = stories.filter(s => s.severity === "low");

  // Critical + High: show full details
  for (const story of [...critical, ...high]) {
    const color = SEV_COLOR[story.severity] || "";
    const icon = SEV_ICON[story.severity] || " ";
    const sev = story.severity.toUpperCase();
    const tasteLabel = story.isTaste ? `  ${c.cyan}[Pro]${c.reset}` : "";

    status(`  ${color}${icon} ${sev}${c.reset}  ${c.bold}${story.title}${c.reset}${tasteLabel}`);

    // Show the best evidence line — the one that proves exploitation
    const ev = story.evidence[0];
    if (ev) {
      const payload = typeof ev.payload === "string" ? ev.payload : JSON.stringify(ev.payload);
      const short = payload.length > 60 ? payload.slice(0, 60) + "…" : payload;
      status(`    ${c.dim}${story.server} →${c.reset} ${story.tool || "protocol"}(${short})`);
    }

    status(`    ${c.dim}→${c.reset} ${story.remediation}`);

    if (story.isTaste) {
      status(`    ${c.cyan}↳ Advanced AI-powered red team tests 25+ encoding variants per vector${c.reset}`);
    }

    status("");
  }

  // Medium: compact list
  if (medium.length > 0) {
    status(`  ${c.yellow}~${c.reset} ${c.dim}${medium.length} medium severity${c.reset}`);
    for (const story of medium) {
      status(`    ${c.yellow}${story.title}${c.reset}  ${c.dim}${story.server}${c.reset}`);
    }
    status("");
  }

  // Low: tally by title — raw list is noise (e.g. 17 protocol handshakes look identical)
  if (low.length > 0) {
    const counts = new Map();
    for (const s of low) {
      const title = s.title.split(" — ")[0];
      counts.set(title, (counts.get(title) || 0) + 1);
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const TOP = 8;
    const top = sorted.slice(0, TOP);
    const more = sorted.length - top.length;
    const formatted = top.map(([t, n]) => n > 1 ? `${t} ×${n}` : t).join(", ");
    const tail = more > 0 ? `, +${more} more type${more > 1 ? "s" : ""}` : "";
    status(`  ${c.dim}  ${low.length} low: ${formatted}${tail}${c.reset}`);
    status("");
  }
}

function printSummary(stories, results, servers, coverage) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const s of stories) counts[s.severity] = (counts[s.severity] || 0) + 1;

  const parts = [];
  if (counts.critical > 0) parts.push(`${c.red}${counts.critical} critical${c.reset}`);
  if (counts.high > 0) parts.push(`${c.orange}${counts.high} high${c.reset}`);
  if (counts.medium > 0) parts.push(`${c.yellow}${counts.medium} medium${c.reset}`);
  if (counts.low > 0) parts.push(`${c.dim}${counts.low} low${c.reset}`);

  const serverCount = servers.length;

  status(`  ${c.dim}${"─".repeat(40)}${c.reset}`);

  if (stories.length === 0) {
    status(`  ${c.green}✓${c.reset} ${c.bold}Clean.${c.reset}  ${c.dim}${serverCount} server${serverCount > 1 ? "s" : ""}, ${coverage.executed} attacks — no exploitable issues${c.reset}`);
  } else {
    status(`  ${c.red}✗${c.reset} ${parts.join(", ")}  ${c.dim}across ${serverCount} server${serverCount > 1 ? "s" : ""}${c.reset}`);
    status(`  ${c.dim}  Better to find it here than in prod.${c.reset}`);
  }

  // Next steps — what to actually do with these findings
  if (stories.length > 0) {
    const criticalOrHigh = counts.critical + counts.high;
    status("");
    status(`  ${c.bold}Next steps${c.reset}`);
    if (criticalOrHigh > 0) {
      status(`  ${c.dim}·${c.reset} Patch the ${criticalOrHigh} ${criticalOrHigh === 1 ? "finding" : "findings"} above — each story includes a ${c.dim}→${c.reset} remediation line.`);
    } else {
      status(`  ${c.dim}·${c.reset} Review medium/low findings — most are hardening opportunities, not exploits.`);
    }
    status(`  ${c.dim}·${c.reset} Re-run ${c.cyan}npx decoy-redteam --live${c.reset} after fixes to verify.`);
    status(`  ${c.dim}·${c.reset} Install ${c.cyan}npx decoy-tripwire init${c.reset} to catch exploitation in the wild.`);
    status(`  ${c.dim}·${c.reset} Export to SARIF for CI: ${c.cyan}npx decoy-redteam --live --sarif > findings.sarif${c.reset}`);
  }

  // Coverage + Pro upsell (only for free users)
  if (!teamMode) {
    const untested = coverage.total - coverage.executed;
    if (untested > 0 && coverage.percentage < 90) {
      status("");
      status(`  ${c.dim}Assessment coverage:${c.reset} ${c.bold}${coverage.percentage}%${c.reset}  ${c.dim}(${coverage.executed} of ${coverage.total} patterns)${c.reset}`);
      status("");
      status(`  ${c.bold}Advanced AI-powered red team${c.reset} adds ${untested} AI-adaptive attack patterns:`);
      if (coverage.layer2 > 0) {
        status(`  ${c.dim}·${c.reset} Payloads generated for your ${coverage.toolCount} tool schemas`);
        status(`  ${c.dim}·${c.reset} 25+ encoding bypass variants per injection vector`);
      }
      if (coverage.layer3 > 0) {
        status(`  ${c.dim}·${c.reset} Cross-server chains across ${coverage.serverCount} servers`);
      }
      status(`  ${c.dim}·${c.reset} Exportable HTML report for security reviews`);
      status(`  ${c.dim}·${c.reset} Continuous red teaming with drift detection`);
      status("");
      status(`  ${c.cyan}npx decoy-redteam --team${c.reset}      Get started`);
      status(`  ${c.dim}decoy.run/pricing${c.reset}             Learn more`);
    }
  }
  status("");
}

function exitWithCode(stories) {
  const hasCritical = stories.some(s => s.severity === "critical");
  const hasHigh = stories.some(s => s.severity === "high");
  process.exit(hasCritical ? 2 : hasHigh ? 1 : 0);
}

// ─── Run ───

main().catch((e) => {
  process.stderr.write(`\n  ${c?.red || ""}Error: ${e.message}${c?.reset || ""}\n\n`);
  process.exit(1);
});
