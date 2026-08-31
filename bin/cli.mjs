#!/usr/bin/env node

// decoy-redteam CLI — autonomous red team for MCP servers

import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { discoverConfigs, probeServers, captureBaselines, planAttacks, executeAttacks, buildStories, closeAll, isInteractiveSideEffectTool } from "../lib/engine.mjs";
import { calculateCoverage } from "../lib/coverage.mjs";
import { detectToolPoisoning } from "../lib/poisoning.mjs";
import { toSarif, toJson } from "../lib/report.mjs";
import { extractSource, extractGitHubSource } from "../lib/source.mjs";
import {
  sendEvent as sendTelemetryEvent,
  flushQueue as flushTelemetryQueue,
  newRunId,
  inferHostFromConfigs,
  maybePrintFirstRunNotice,
  maybePrintClaimURL,
  summarizeRedteamForTelemetry,
} from "../lib/telemetry.mjs";
import {
  EXIT_USAGE,
  findUnknownFlag,
  reportUnknownFlag,
  reportUnknownCommand,
  resolveColor,
  canPrompt,
  fetchWithTimeout,
  isTimeoutError,
  onInterrupt,
} from "../lib/argv.mjs";

// ─── Version ───

const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));
const VERSION = PKG.version;

// ─── Args ───

const args = process.argv.slice(2);

// Short aliases are declared, never derived. The old `flag()` matched
// `-${name[0]}` for every long flag, which quietly made `-n` mean both
// --no-color and --no-telemetry, `-p` trigger the --pro deprecation warning,
// and `-t` turn on paid team mode. Only these five have short forms.
// No short form for --live on purpose: `-l` previously did nothing, and
// silently promoting it to "execute attacks" is not a change to make to a tool
// that fires payloads at live servers.
const SHORT = { h: "help", V: "version", q: "quiet" };

// Every flag decoy-redteam accepts, so a typo is an error rather than a
// silently different run.
const KNOWN_FLAGS = new Set([
  "live", "full", "team", "pro", "target", "category", "json", "sarif", "brief",
  "quiet", "q", "no-input", "no-color", "color", "no-telemetry",
  "token", "token-file", "repo", "version", "V", "help", "h",
]);

const flag = (name) => {
  if (args.includes(`--${name}`)) return true;
  for (const [short, long] of Object.entries(SHORT)) {
    if (long === name && args.includes(`-${short}`)) return true;
  }
  return false;
};
const flagVal = (name) => {
  const arg = args.find(a => a.startsWith(`--${name}=`));
  return arg ? arg.slice(name.length + 3) : null;
};

const jsonMode = flag("json");
const sarifMode = flag("sarif");
const dryRun = !flag("live");
const fullMode = flag("full");
const helpMode = flag("help");
const versionMode = flag("version");
const quietMode = flag("quiet");
const briefMode = flag("brief");
// --team is the primary flag; --pro is a deprecated alias kept for existing scripts.
const teamMode = flag("team") || flag("pro");
if (flag("pro") && !flag("team")) {
  process.stderr.write("[deprecated] --pro is renamed to --team. Please update your scripts.\n");
}
const targetServer = flagVal("target");
const categoryFilter = flagVal("category")?.split(",");
const noTelemetry = flag("no-telemetry");
const TOKEN_FILE = join(homedir(), ".decoy", "token");
function loadStoredToken() {
  try {
    const t = readFileSync(TOKEN_FILE, "utf8").trim();
    return t.length >= 16 ? t : null;
  } catch { return null; }
}
function saveStoredToken(token) {
  mkdirSync(dirname(TOKEN_FILE), { recursive: true });
  writeFileSync(TOKEN_FILE, token + "\n", { mode: 0o600 });
}
// tokenArg = explicit upload consent (uploads results to dashboard at the end
// of a run). Only --token= and DECOY_TOKEN qualify — the stored ~/.decoy/token
// is a sign-in convenience, not blanket telemetry consent. It's consulted only
// inside `if (teamMode)` below as auth for the paid feature the user explicitly
// opted into via --team.
// A token on the command line is readable by every process on the box via
// `ps` and lands in shell history. --token-file/DECOY_TOKEN_FILE is the form
// to use in CI.
function loadTokenFile(path) {
  try {
    const t = readFileSync(path, "utf8").trim();
    if (t.length < 16) {
      process.stderr.write(`error: token file ${path} does not contain a valid token\n`);
      process.exit(EXIT_USAGE);
    }
    return t;
  } catch (e) {
    process.stderr.write(`error: cannot read token file ${path}: ${e.message}\n`);
    process.exit(EXIT_USAGE);
  }
}
const tokenFileArg = flagVal("token-file") || process.env.DECOY_TOKEN_FILE;
let tokenArg = (tokenFileArg ? loadTokenFile(tokenFileArg) : null)
  || flagVal("token")
  || process.env.DECOY_TOKEN;
const repoArg = flagVal("repo");
const API_BASE = (process.env.DECOY_API_BASE || "https://app.decoy.run/api").replace(/\/$/, "");

// ─── Color support ───

const isTTY = process.stderr.isTTY;
const noColor = !resolveColor(args, process.stderr);

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

// ─── Argument validation ───

const unknownFlag = findUnknownFlag(args, KNOWN_FLAGS);
if (unknownFlag) {
  reportUnknownFlag(unknownFlag, KNOWN_FLAGS, "decoy-redteam");
  process.exit(EXIT_USAGE);
}

// decoy-redteam has no subcommands — a stray positional is almost always a
// flag typed without its dashes, or a server name that belongs in --target.
const positional = args.filter(a => !a.startsWith("-"));
if (positional.length > 0) {
  reportUnknownCommand(positional[0], [], "decoy-redteam");
  process.stderr.write(`  decoy-redteam takes no subcommands. To scope a run: --target=${positional[0]}\n`);
  process.exit(EXIT_USAGE);
}

const CATEGORIES = [
  "input-injection", "prompt-injection", "privilege-escalation",
  "credential-exposure", "protocol-attacks", "schema-boundary",
];
for (const cat of categoryFilter || []) {
  const name = cat.trim();
  if (!name || CATEGORIES.includes(name)) continue;
  process.stderr.write(`error: unknown category "${name}"\n`);
  process.stderr.write(`  Valid: ${CATEGORIES.join(", ")}\n`);
  process.exit(EXIT_USAGE);
}

if (jsonMode && sarifMode) {
  process.stderr.write("error: --json and --sarif are mutually exclusive\n");
  process.exit(EXIT_USAGE);
}

// Fail here rather than after spawning and probing every configured server:
// a CI run that can't answer the confirmation prompt should find out in
// milliseconds, not at the end of a discovery pass.
if (!dryRun && process.env.DECOY_REDTEAM_CONFIRM !== "yes" && !canPrompt(args)) {
  process.stderr.write("error: --live needs an interactive terminal to confirm\n");
  process.stderr.write("  For CI, set DECOY_REDTEAM_CONFIRM=yes to accept the authorization warning.\n");
  process.exit(EXIT_USAGE);
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

// Tracked so the interrupt handler can clear the line and restore the cursor
// before the shell prompt comes back.
let activeSpinner = null;

function spinner(label) {
  // Non-TTY (and machine-readable modes): no animation, but still surface the final status message
  // so phase transitions are visible in piped output, CI logs, and test harnesses.
  if (!isTTY || quietMode || jsonMode || sarifMode) {
    return { stop(msg) { if (msg) status(msg); } };
  }
  let i = 0;
  const started = Date.now();
  process.stderr.write("\x1b[?25l");
  const id = setInterval(() => {
    // Attack execution can run for minutes. Past a few seconds, show elapsed
    // time so a long phase reads as working rather than wedged.
    const secs = Math.round((Date.now() - started) / 1000);
    const elapsed = secs >= 3 ? ` ${c.dim}(${secs}s)${c.reset}` : "";
    process.stderr.write(`\r\x1b[K  ${c.dim}${SPINNER_FRAMES[i++ % SPINNER_FRAMES.length]} ${label}${c.reset}${elapsed}`);
  }, 80);
  const handle = {
    stop(msg) {
      clearInterval(id);
      process.stderr.write("\r\x1b[K\x1b[?25h");
      if (activeSpinner === handle) activeSpinner = null;
      if (msg) status(msg);
    },
  };
  activeSpinner = handle;
  return handle;
}

// ─── Browser-based token capture ───
// Same pattern as decoy-scan loginInteractive: opens the dashboard's Setup &
// Tokens section, prompts for the user to paste their token, persists it to
// ~/.decoy/token so subsequent --team runs don't need --token=.

function openBrowser(url) {
  const cmd = process.platform === "darwin" ? "open"
    : process.platform === "win32" ? "cmd"
    : "xdg-open";
  const browserArgs = process.platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    spawn(cmd, browserArgs, { stdio: "ignore", detached: true }).unref();
    return true;
  } catch { return false; }
}

async function getTokenViaBrowser() {
  if (!canPrompt(args)) {
    process.stderr.write("error: sign-in needs an interactive terminal\n");
    process.stderr.write("  Pass an existing token instead: --token-file=PATH, or set DECOY_TOKEN_FILE.\n");
    process.exit(EXIT_USAGE);
  }
  const url = "https://app.decoy.run/dashboard?tab=settings#s-setup";
  status("");
  status(`  ${c.bold}Sign in to Decoy${c.reset}`);
  status(`  ${c.dim}Free, ~30 seconds. Email-only — no card, no password.${c.reset}`);
  status("");
  status(`  ${c.dim}1.${c.reset} Opening ${c.cyan}${url}${c.reset}`);
  openBrowser(url);
  status(`  ${c.dim}2.${c.reset} Sign in (or sign up if it's your first time)`);
  status(`  ${c.dim}3.${c.reset} Copy your token from Setup & Tokens`);
  status("");

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const token = await new Promise(resolve => {
    rl.question(`  Paste your token: `, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });

  if (!token) {
    status("");
    status(`  ${c.dim}Cancelled. Re-run when you're ready.${c.reset}`);
    return null;
  }
  if (token.length < 16) {
    status(`  ${c.red}That doesn't look like a valid token (too short).${c.reset}`);
    return null;
  }
  return token;
}

// ─── Confirm prompt ───

async function confirm(message) {
  // CI/testing escape hatch — not a CLI flag, deliberate friction preserved
  if (process.env.DECOY_REDTEAM_CONFIRM === "yes") return true;

  if (!canPrompt(args)) {
    process.stderr.write("error: --live needs an interactive terminal to confirm\n");
    process.stderr.write("  For CI, set DECOY_REDTEAM_CONFIRM=yes to accept the authorization warning.\n");
    process.exit(EXIT_USAGE);
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
  --color          Force color output
  --no-input       Never prompt; fail instead of waiting for input
  --no-telemetry   Disable anonymized telemetry (or set DECOY_TELEMETRY=0)

${c.bold}Advanced AI-powered red team${c.reset} (Team / Business plans)
  --team               AI-adaptive attacks + source code analysis
  --team --token=TOKEN Authenticate with Decoy Guard account (visible in \`ps\`)
  --team --token-file=PATH  Read the token from a file — prefer this in CI
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
    1  High-risk findings, or the command failed
    2  Critical findings
  130  Interrupted with Ctrl-C

${c.bold}Environment${c.reset}
  DECOY_TOKEN                API token (--token-file is safer)
  DECOY_TOKEN_FILE           Path to a file containing the API token
  DECOY_REDTEAM_CONFIRM=yes  Skip the --live confirmation prompt (CI)
  DECOY_REDTEAM_AUTHORIZED=1 Suppress the authorization warning
  DECOY_API_BASE             Override the API endpoint
  GITHUB_TOKEN               Auth for --repo on private repositories
  DECOY_TELEMETRY=0          Disable anonymized telemetry
  NO_COLOR                   Disable colored output

${c.bold}Agent integration${c.reset}
  This CLI ships with AGENTS.md for AI agent reference.
  Use --json for structured output. Use --brief for minimal summaries.
  Set DECOY_REDTEAM_CONFIRM=yes to skip confirmation in CI/CD.

${c.bold}Learn more${c.reset}
  Docs         ${c.cyan}https://decoy.run/docs${c.reset}
  Report a bug ${c.cyan}https://github.com/decoy-run/decoy-redteam/issues${c.reset}`);
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
    const res = await fetchWithTimeout(`${API_BASE}/redteam/upload`, {
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
  // One run_id for the whole invocation. Fire cli.invoked first thing
  // so the funnel denominator counts even bounced/crashed runs.
  const runId = newRunId();
  trackTelemetry(flushTelemetryQueue());

  // Ctrl-C must reap the MCP servers we spawned, or they linger holding
  // stdio. A second Ctrl-C skips that and exits immediately.
  const servers = [];
  onInterrupt(() => {
    activeSpinner?.stop();
    closeAll(servers);
  });

  status(`\n  ${c.bold}decoy-redteam${c.reset} ${c.dim}v${VERSION}${c.reset}\n`);

  // cli.invoked — earliest event. Captures who started us, in what
  // mode, with what token state. Pre-discovery so even bouncing users
  // produce a signal.
  trackTelemetry(sendTelemetryEvent({
    tool: "decoy-redteam",
    version: VERSION,
    event: "cli.invoked",
    runId,
    payload: {
      mode: jsonMode ? "json" : sarifMode ? "sarif" : briefMode ? "brief" : "human",
      live: !dryRun,
      teamMode,
      fullMode,
      hasToken: !!tokenArg,
      hasRepo: !!repoArg,
    },
    disabled: noTelemetry,
  }));

  // Authorization warning — required for a red team tool
  if (process.env.DECOY_REDTEAM_AUTHORIZED !== "1") {
    if (dryRun) {
      status(`  ${c.yellow}⚠️${c.reset} decoy-redteam tests ${c.bold}YOUR OWN${c.reset} MCP servers for vulnerabilities.`);
      status(`     Only run against servers you own or have explicit authorization to test.`);
      status(`     By proceeding, you confirm you have authorization for this security test.\n`);
    }
    // In --live mode, the warning is shown as part of the confirmation prompt below
  }

  // Team mode
  if (teamMode) {
    // --team is the user explicitly opting into the paid feature. Promote a
    // stored ~/.decoy/token here (only here) to spare them another paste.
    if (!tokenArg) {
      const stored = loadStoredToken();
      if (stored) tokenArg = stored;
    }
    // Still no token → run the browser sign-in flow (TTY) or print a
    // copy-pasteable hint (non-TTY / JSON / SARIF).
    if (!tokenArg) {
      const canPrompt = isTTY && !jsonMode && !sarifMode && !briefMode;
      if (canPrompt) {
        status(`  ${c.bold}Advanced AI-powered red team${c.reset} — adaptive attacks, cross-server chains, exportable reports`);
        const captured = await getTokenViaBrowser();
        if (!captured) process.exit(1);
        try {
          saveStoredToken(captured);
          status(`  ${c.green}✓${c.reset} ${c.dim}Saved to ~/.decoy/token. Future --team runs won't need --token.${c.reset}\n`);
        } catch {
          // Non-fatal: keep going with the in-memory token even if we can't persist.
        }
        tokenArg = captured;
      } else {
        status(`  ${c.bold}Advanced AI-powered red team${c.reset} — adaptive attacks, cross-server chains, exportable reports\n`);
        status(`  Available on Decoy Guard paid plans. Sign up and pass your token:\n`);
        status(`  ${c.cyan}npx decoy-redteam --team --token=YOUR_TOKEN${c.reset}\n`);
        status(`  Don't have an account? Get started at ${c.underline}decoy.run/pricing${c.reset}\n`);
        process.exit(0);
      }
    }

    // Validate the token (whether from flag, env, stored, or pasted) against Guard.
    try {
      const res = await fetchWithTimeout(`${API_BASE}/billing?token=${encodeURIComponent(tokenArg)}`, {}, 15000);
      const billing = await res.json();
      const paidPlan = billing.plan === "team" || billing.plan === "pro" || billing.plan === "business";
      if (paidPlan) {
        const usage = billing.redteamUsage || {};
        const remaining = (usage.limit || 20) - (usage.used || 0);
        const planLabel = billing.plan === "business" ? "Business" : "Team";
        status(`  ${c.green}✓${c.reset} Guard ${planLabel}  ${c.dim}${remaining} assessments remaining this month${c.reset}\n`);
      } else {
        status(`  ${c.yellow}Your account is on the ${billing.plan || "free"} plan.${c.reset}`);
        status(`  Upgrade to Team for AI-adaptive attacks and exportable reports.\n`);
        status(`  ${c.cyan}https://app.decoy.run/dashboard?tab=settings#s-plan${c.reset}\n`);
        process.exit(0);
      }
    } catch {
      status(`  ${c.red}Could not verify account.${c.reset} Check your token and try again.\n`);
      process.exit(1);
    }
  }

  // Discover configs
  const configs = discoverConfigs();
  const host = inferHostFromConfigs(configs);

  // scan.discovery analog for redteam — what hosts/servers exist.
  trackTelemetry(sendTelemetryEvent({
    tool: "decoy-redteam",
    version: VERSION,
    event: "redteam.plan",
    runId,
    host,
    payload: {
      hostCount: configs.length,
      serverCount: new Set(configs.flatMap(c => Object.keys(c.servers || {}))).size,
      hosts: configs.map(c => c.host).slice(0, 10),
    },
    disabled: noTelemetry,
  }));

  if (configs.length === 0) {
    // Fire telemetry even on empty discovery — same fix as scan's
    // empty-config path. exitWithCode awaits all tracked promises.
    trackTelemetry(sendTelemetryEvent({
      tool: "decoy-redteam",
      version: VERSION,
      event: "redteam.complete",
      runId,
      host,
      payload: { noConfigs: true, hostsChecked: 7 },
      disabled: noTelemetry,
    }));
    if (jsonMode) {
      const empty = { timestamp: new Date().toISOString(), version: VERSION, stories: [], coverage: { executed: 0, total: 0, percentage: 100 }, summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 } };
      await new Promise(r => process.stdout.write(JSON.stringify(empty, null, 2) + "\n", r));
    } else if (sarifMode) {
      const empty = { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "decoy-redteam", version: VERSION, rules: [] } }, results: [] }] };
      await new Promise(r => process.stdout.write(JSON.stringify(empty, null, 2) + "\n", r));
    } else {
      status(`  No MCP configurations found.\n  Checked: Claude Desktop, Cursor, Windsurf, VS Code, Claude Code, Zed, Cline\n\n  Hint: Create .mcp.json in your project or configure an MCP client. See https://decoy.run/docs`);
      maybePrintFirstRunNotice({ tool: "decoy-redteam", stream: process.stderr });
      maybePrintClaimURL({ tool: "decoy-redteam", stream: process.stderr });
    }
    await exitWithCode([]);
    return;
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

  // Passive tool-poisoning scan — reads the advertised tool surface (no payloads
  // sent), so it runs in dry-run too and flows through every output path.
  const poisonStories = detectToolPoisoning(connected);

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
      const res = await fetchWithTimeout(`${API_BASE}/redteam/plan`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${tokenArg}` },
        body: JSON.stringify({ servers: serverSchemas }),
      }, 120000);
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
        sp3.stop(`  ${c.yellow}!${c.reset} ${c.dim}AI-adaptive unavailable: ${err.error || res.status} — falling back to deterministic attacks${c.reset}\n`);
      }
    } catch (e) {
      sp3.stop(`  ${c.yellow}!${c.reset} ${c.dim}AI-adaptive unavailable: ${e.message} — falling back to deterministic attacks${c.reset}\n`);
    }
  }

  if (plan.length === 0 && poisonStories.length === 0) {
    status("  No applicable attacks for the discovered tools.\n  Hint: The discovered tools don't match any attack patterns. Try --category to see available categories\n");
    closeAll(servers);
    process.exit(0);
  }

  // Dry-run mode (or nothing executable but the tool surface is poisoned):
  // report passive findings + the attack plan, then exit on severity.
  if (dryRun || plan.length === 0) {
    if (jsonMode || sarifMode) {
      const meta = { version: VERSION, mode: "dry-run", servers: connected.length, tools: toolCount };
      const cov = { executed: 0, total: plan.length, percentage: 0 };
      const out = jsonMode ? toJson(poisonStories, cov, meta) : toSarif(poisonStories, cov, { version: VERSION });
      closeAll(servers);
      await new Promise(r => process.stdout.write(JSON.stringify(out, null, 2) + "\n", r));
      await exitWithCode(poisonStories);
      return;
    }

    if (poisonStories.length > 0) {
      status(`  ${c.dim}── Passive Findings · tool poisoning (no execution needed) ──${c.reset}\n`);
      printStories(poisonStories);
    }

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

    // Dry-run: nothing executed yet, so percentage is uninformative. Show
    // the planned count instead and tease the paid tier qualitatively —
    // not with an invented delta.
    status(`  ${c.dim}Planned:${c.reset} ${c.bold}${plan.length} attacks${c.reset} across ${connected.length} server${connected.length > 1 ? "s" : ""}`);
    if (!teamMode) {
      status(`  ${c.dim}Advanced AI-powered red team adds AI-adaptive payloads and encoding bypasses  decoy.run/pricing${c.reset}`);
    }

    status(`\n  ${c.cyan}npx decoy-redteam --live${c.reset}                Execute attacks`);
    status(`  ${c.cyan}npx decoy-redteam --live --target=NAME${c.reset}  Target one server\n`);

    status(`  ${c.dim}★ If decoy-redteam helps, a star helps us prioritize what to build:${c.reset}`);
    status(`  ${c.dim}  ${c.cyan}https://github.com/decoy-run/decoy-redteam${c.reset}\n`);

    closeAll(servers);
    // Passive poisoning findings set the exit code even in dry-run, so CI can
    // catch a hostile tool surface without ever going --live.
    await exitWithCode(poisonStories);
    return;
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

  // Baseline capture — one benign call per tool before any attack. Findings
  // whose indicators also match the baseline get suppressed (they were already
  // in the tool's normal output, not attack-specific). Timing thresholds
  // adapt to the tool's natural latency to dampen cold-start FPs.
  const baselineCount = connected.reduce((n, s) => n + s.tools.filter(t => !isInteractiveSideEffectTool(t)).length, 0);
  if (baselineCount > 0) {
    const spB = spinner(`Calibrating baselines (${baselineCount} tools)…`);
    let lastBaseUpdate = 0;
    const bStart = performance.now();
    await captureBaselines(connected, {
      onProgress: ({ completed, total }) => {
        if (!isTTY || quietMode || jsonMode || sarifMode) return;
        const now = Date.now();
        if (now - lastBaseUpdate > 150) {
          const pct = Math.round((completed / total) * 100);
          process.stderr.write(`\r\x1b[K  ${c.dim}${SPINNER_FRAMES[0]} Calibrating baselines · ${pct}%${c.reset}`);
          lastBaseUpdate = now;
        }
      },
    });
    const captured = connected.reduce((n, s) => n + (s.baselines?.size || 0), 0);
    const bElapsed = ((performance.now() - bStart) / 1000).toFixed(1);
    spB.stop(`  ${c.dim}${captured}/${baselineCount} baselines captured in ${bElapsed}s${c.reset}`);
  }

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

      const iterRes = await fetchWithTimeout(`${API_BASE}/redteam/iterate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${tokenArg}` },
        body: JSON.stringify({ servers: serverSchemas, results: resultSummary }),
      }, 120000);

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

  // Build stories from all results. Passive poisoning findings (collected at
  // connect time, before any payload) lead — they're high-confidence and need
  // no execution to confirm.
  const stories = [...poisonStories, ...buildStories(allResults)];

  // Coverage: count Layer 1 deterministic attacks only for the denominator calculation
  // Pro attacks are ADDITIONAL — they don't reduce the "what's left" estimate
  const l1Results = results.filter(r => r.outcome !== "error");
  const proResults = iterateResults.filter(r => r.outcome !== "error");
  // Planned = total attacks in the deterministic plan. Executed = ones
  // that returned a non-error result. Honest percentage.
  const coverage = calculateCoverage(connected, {
    executed: l1Results.length,
    planned: plan.length,
  });
  // Pro/Team adds AI-adaptive attacks on top — fold them in so the
  // displayed numbers reflect the full run.
  if (proResults.length > 0) {
    coverage.executed += proResults.length;
    coverage.total += proResults.length;
    coverage.percentage = coverage.total > 0
      ? Math.round((coverage.executed / coverage.total) * 100)
      : 100;
  }

  // Kick off the redteam.complete event alongside output rendering.
  // exitWithCode awaits the whole tracked telemetry set before exit.
  trackTelemetry(sendTelemetryEvent({
    tool: "decoy-redteam",
    version: VERSION,
    event: "redteam.complete",
    runId,
    host,
    payload: summarizeRedteamForTelemetry({
      stories,
      coverage,
      servers: connected,
      mode: safe ? "safe" : (fullMode ? "full" : "default"),
    }),
    disabled: noTelemetry,
  }));

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
    await exitWithCode(stories);
    return;
  }

  if (jsonMode) {
    const meta = { version: VERSION, mode: safe ? "safe" : "full", servers: connected.length, tools: toolCount };
    const json = JSON.stringify(toJson(stories, coverage, meta), null, 2);
    closeAll(servers);
    await new Promise(r => process.stdout.write(json + "\n", r));
    await exitWithCode(stories);
    return;
  }

  if (sarifMode) {
    const meta = { version: VERSION };
    const json = JSON.stringify(toSarif(stories, coverage, meta), null, 2);
    closeAll(servers);
    await new Promise(r => process.stdout.write(json + "\n", r));
    await exitWithCode(stories);
    return;
  }

  // Terminal output
  printStories(stories);
  printSummary(stories, results, connected, coverage);

  // First-run telemetry notice — printed once per machine, after the user has
  // already seen value. Skip in machine-readable output modes.
  maybePrintFirstRunNotice({ tool: "decoy-redteam", stream: process.stderr });
  maybePrintClaimURL({ tool: "decoy-redteam", stream: process.stderr });

  closeAll(servers);
  await exitWithCode(stories);
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
    const owaspTag = story.owasp ? `  ${c.dim}[${story.owasp}]${c.reset}` : "";

    status(`  ${color}${icon} ${sev}${c.reset}  ${c.bold}${story.title}${c.reset}${owaspTag}`);

    // Show the best evidence line — the one that proves exploitation
    const ev = story.evidence[0];
    if (ev) {
      const payload = typeof ev.payload === "string" ? ev.payload : JSON.stringify(ev.payload);
      const short = payload.length > 60 ? payload.slice(0, 60) + "…" : payload;
      status(`    ${c.dim}${story.server} →${c.reset} ${story.tool || "protocol"}(${short})`);

      // Response evidence — what came back from the server, the proof. This is
      // the most-screenshottable part of the output. Skip for the noError-only
      // "accepted" case (no exfil evidence to display).
      if (ev.response && ev.outcome === "vulnerable") {
        const lines = String(ev.response).split("\n").slice(0, 4);
        const maxLen = 64;
        const clipped = lines.map(l => l.length > maxLen ? l.slice(0, maxLen) + "…" : l);
        if (clipped.length > 0 && clipped[0].trim() !== "") {
          status(`    ${c.dim}┌─ Response ${"─".repeat(maxLen - 9)}${c.reset}`);
          for (const l of clipped) {
            status(`    ${c.dim}│${c.reset} ${l}`);
          }
          status(`    ${c.dim}└${"─".repeat(maxLen + 1)}${c.reset}`);
        }
      }
    }

    status(`    ${c.dim}→${c.reset} ${story.remediation}`);
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

  // Pro upsell (only for free users). No invented coverage delta — we no
  // longer claim "we cover X% and paid covers Y% more." The qualitative
  // pitch (AI-adaptive, encoding bypass, cross-server chains) is what we
  // actually ship.
  if (!teamMode) {
    status("");
    status(`  ${c.dim}Free tier: ${coverage.executed} deterministic attacks across ${coverage.serverCount} server${coverage.serverCount > 1 ? "s" : ""}.${c.reset}`);
    status("");
    status(`  ${c.bold}Advanced AI-powered red team${c.reset} adds:`);
    status(`  ${c.dim}·${c.reset} AI-adaptive payloads generated for your tool schemas`);
    status(`  ${c.dim}·${c.reset} 25+ encoding bypass variants per injection vector`);
    if (coverage.serverCount >= 2) {
      status(`  ${c.dim}·${c.reset} Cross-server chains across ${coverage.serverCount} servers`);
    }
    status(`  ${c.dim}·${c.reset} Exportable HTML report for security reviews`);
    status(`  ${c.dim}·${c.reset} Continuous red teaming on a schedule`);
    status("");
    status(`  ${c.cyan}npx decoy-redteam --team${c.reset}      Get started`);
    status(`  ${c.dim}decoy.run/pricing${c.reset}             Learn more`);
  }

  status("");
  status(`  ${c.dim}★ If decoy-redteam helps, a star helps us prioritize what to build:${c.reset}`);
  status(`  ${c.dim}  ${c.cyan}https://github.com/decoy-run/decoy-redteam${c.reset}`);
  status("");
}

// All telemetry promises are tracked here so exitWithCode awaits them
// all before process.exit — without this, the fire-and-forget
// cli.invoked/redteam.plan calls and the queue-drain POST get killed
// mid-flight and never finish. Set as a const array; each tracked
// promise wraps its own .catch so awaitall never rejects.
const pendingTelemetry = [];
function trackTelemetry(p) {
  if (p && typeof p.then === "function") pendingTelemetry.push(p.catch(() => {}));
  return p;
}

async function exitWithCode(stories) {
  if (pendingTelemetry.length > 0) {
    try { await Promise.allSettled(pendingTelemetry); } catch { /* never fail a run on telemetry */ }
    pendingTelemetry.length = 0;
  }
  const hasCritical = stories.some(s => s.severity === "critical");
  const hasHigh = stories.some(s => s.severity === "high");
  process.exit(hasCritical ? 2 : hasHigh ? 1 : 0);
}

// ─── Run ───

main().catch((e) => {
  // Exits 1, as it always has. Changing a published exit code could break a
  // pipeline that branches on it — the `error` key below is how a machine
  // consumer tells a crash apart from "high-risk findings".
  if (jsonMode || sarifMode) {
    process.stdout.write(JSON.stringify({
      tool: "decoy-redteam",
      version: VERSION,
      error: e.message,
      exitCode: 1,
    }) + "\n");
  }
  const detail = isTimeoutError(e) ? `${e.message} (timed out)` : e.message;
  process.stderr.write(`\n  ${c?.red || ""}error:${c?.reset || ""} ${detail}\n`);
  process.stderr.write(`  ${c?.dim || ""}This is a bug in decoy-redteam. Please report it:${c?.reset || ""}\n`);
  process.stderr.write(`  ${c?.dim || ""}https://github.com/decoy-run/decoy-redteam/issues/new${c?.reset || ""}\n\n`);
  process.exit(1);
});
