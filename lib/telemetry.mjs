// Anonymous telemetry client (v2 envelope) for decoy-* CLIs.
//
// Default: ON. Every event carries:
//   { schema_version: 2, tool, version, installId, accountId?, event,
//     event_id, run_id, ts, env: { node, platform, arch, ci, host, locale },
//     payload }
//
// Three durability guarantees:
//   1. Retry — 1 retry with 200→800ms backoff on timeout / 5xx.
//   2. Persistent queue — on final failure events append to
//      ~/.decoy/telemetry-queue.jsonl (capped 1000, FIFO). The next
//      CLI run drains the queue first as a batched POST.
//   3. Dedup — every event carries a UUID event_id, so retries +
//      queue-drain replays are server-side idempotent.
//
// Opt-out: DECOY_TELEMETRY=0 env var or `--no-telemetry` CLI flag.
// Both routes silently no-op the network call (queue is not appended).
//
// First-run disclosure: a single line printed once per machine,
// cached at ~/.decoy/telemetry-notice-shown. Not a modal.

import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, statSync, truncateSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { decoyDir, getOrCreateInstallId } from "./install_id.mjs";

const SCHEMA_VERSION = 2;
const API_BASE = process.env.DECOY_API_BASE
  ? process.env.DECOY_API_BASE.replace(/\/+$/, "")
  : "https://app.decoy.run";
const TELEMETRY_URL = `${API_BASE}/api/telemetry`;
const REQUEST_TIMEOUT_MS = 4000;
const RETRY_DELAYS_MS = [200, 800];
const QUEUE_MAX_EVENTS = 1000;
const QUEUE_FLUSH_BATCH = 50;

const ALLOWED_PLATFORMS = new Set(["darwin", "linux", "win32", "freebsd", "openbsd", "sunos", "aix"]);
const ALLOWED_ARCHS = new Set(["x64", "arm64", "arm", "ia32", "ppc64", "s390x"]);
const ALLOWED_HOSTS = new Set([
  "claude-desktop", "cursor", "windsurf", "vscode", "claude-code", "zed", "cline",
  "ci", "cli", "unknown",
]);

const QUEUE_FILE = () => join(decoyDir(), "telemetry-queue.jsonl");

// ─── Opt-out ─────────────────────────────────────────────────────

export function telemetryDisabled({ flag = false } = {}) {
  if (flag) return true;
  const env = String(process.env.DECOY_TELEMETRY ?? "").toLowerCase();
  return env === "0" || env === "false" || env === "off" || env === "no";
}

// ─── Environment detection ───────────────────────────────────────
// Cached on first call; cheap but no need to recompute per event.

let _envCache = null;
function detectEnv({ host } = {}) {
  if (_envCache && !host) return _envCache;
  const platform = ALLOWED_PLATFORMS.has(process.platform) ? process.platform : null;
  const arch = ALLOWED_ARCHS.has(process.arch) ? process.arch : null;
  let locale = null;
  try {
    locale = Intl.DateTimeFormat().resolvedOptions().locale.slice(0, 12);
  } catch { /* very old node, leave null */ }
  const env = {
    node: process.version,
    platform,
    arch,
    ci: isCI(),
    host: ALLOWED_HOSTS.has(host) ? host : (isCI() ? "ci" : "cli"),
    locale,
  };
  // Remove null/undefined fields so the worker's strict-vocabulary
  // validator doesn't have to ignore them.
  for (const k of Object.keys(env)) if (env[k] == null) delete env[k];
  if (!host) _envCache = env;
  return env;
}

// Industry-standard CI detection. Any of these env vars present and
// not "false" → CI environment.
function isCI() {
  const flags = [
    "CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI",
    "CIRCLECI", "TRAVIS", "BUILDKITE", "JENKINS_URL", "JENKINS_HOME",
    "TEAMCITY_VERSION", "TF_BUILD", "BITBUCKET_BUILD_NUMBER",
    "APPVEYOR", "CODEBUILD_BUILD_ID", "DRONE", "SEMAPHORE", "HUDSON_URL",
  ];
  for (const f of flags) {
    const v = process.env[f];
    if (v && String(v).toLowerCase() !== "false") return true;
  }
  return false;
}

// Infer host from discovered MCP configs (returned by discoverConfigs).
// Most-frequent host wins; ties pick by stable order. Falls back to
// "cli" / "ci".
export function inferHostFromConfigs(configs) {
  if (!Array.isArray(configs) || configs.length === 0) return null;
  const counts = new Map();
  for (const c of configs) {
    const h = normalizeHost(c?.host);
    if (h) counts.set(h, (counts.get(h) || 0) + Object.keys(c.servers || {}).length);
  }
  if (counts.size === 0) return null;
  let best = null, bestCount = -1;
  for (const [k, v] of counts) {
    if (v > bestCount) { best = k; bestCount = v; }
  }
  return best;
}

function normalizeHost(s) {
  if (!s || typeof s !== "string") return null;
  const lower = s.toLowerCase();
  if (lower.includes("claude desktop") || lower === "claude") return "claude-desktop";
  if (lower.includes("cursor")) return "cursor";
  if (lower.includes("windsurf")) return "windsurf";
  if (lower.includes("vs code") || lower === "vscode") return "vscode";
  if (lower.includes("claude code")) return "claude-code";
  if (lower.includes("zed")) return "zed";
  if (lower.includes("cline")) return "cline";
  return null;
}

// ─── Envelope builder ────────────────────────────────────────────

export function newRunId() {
  return randomUUID();
}

export function buildEnvelope({ tool, version, event, payload, runId, host, accountId }) {
  let installId;
  try { installId = getOrCreateInstallId(); }
  catch { installId = null; }
  if (!installId) return null;
  return {
    schema_version: SCHEMA_VERSION,
    tool,
    version,
    installId,
    accountId: accountId || null,
    event,
    event_id: randomUUID(),
    run_id: runId || randomUUID(),
    ts: new Date().toISOString(),
    env: detectEnv({ host }),
    payload: payload ?? null,
  };
}

// ─── Network: send with retry ────────────────────────────────────

async function httpPost(body) {
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      const res = await fetch(TELEMETRY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status >= 200 && res.status < 300) return { ok: true, status: res.status };
      if (res.status >= 400 && res.status < 500) return { ok: false, status: res.status, fatal: true };
      // 5xx — retry
    } catch { /* network / timeout — retry */ }
    if (attempt < RETRY_DELAYS_MS.length) {
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
  }
  return { ok: false, fatal: false };
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Persistent queue ────────────────────────────────────────────
// Append-only JSONL. On drain: read, ship as batched POST, truncate
// on success. Cap at QUEUE_MAX_EVENTS — older entries get dropped
// when the cap is hit (FIFO).

function appendToQueue(envelope) {
  try {
    const dir = decoyDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const file = QUEUE_FILE();
    // Cheap cap enforcement: if file exists and is huge, roll it.
    // Sized in bytes — assume average envelope ~1KB.
    if (existsSync(file)) {
      try {
        const size = statSync(file).size;
        if (size > QUEUE_MAX_EVENTS * 1024) {
          // Drop oldest half. Simple approach — read tail, write back.
          const lines = readFileSync(file, "utf8").split("\n").filter(Boolean);
          const keep = lines.slice(-Math.floor(QUEUE_MAX_EVENTS / 2));
          writeFileSync(file, keep.join("\n") + "\n", { mode: 0o600 });
        }
      } catch { /* size check best-effort */ }
    }
    appendFileSync(file, JSON.stringify(envelope) + "\n", { mode: 0o600 });
  } catch { /* persisting failed; nothing we can do */ }
}

function readQueue() {
  const file = QUEUE_FILE();
  if (!existsSync(file)) return [];
  try {
    return readFileSync(file, "utf8")
      .split("\n")
      .filter(Boolean)
      .map(line => { try { return JSON.parse(line); } catch { return null; } })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function clearQueue() {
  const file = QUEUE_FILE();
  if (!existsSync(file)) return;
  try { truncateSync(file, 0); } catch { /* best-effort */ }
}

// Drain the persistent queue. Best-effort; never throws. Returns the
// number of events successfully shipped. Callers can either await
// this at CLI start or fire-and-forget — both are safe.
export async function flushQueue() {
  if (telemetryDisabled()) return 0;
  const events = readQueue();
  if (events.length === 0) return 0;
  let totalSent = 0;
  // Ship in batches of QUEUE_FLUSH_BATCH so we stay under the worker
  // body cap. Keep all successfully-shipped events out of the queue;
  // re-write any that fail (server returned fatal 4xx) — no point in
  // looping forever on malformed events.
  const remaining = [];
  for (let i = 0; i < events.length; i += QUEUE_FLUSH_BATCH) {
    const batch = events.slice(i, i + QUEUE_FLUSH_BATCH);
    const r = await httpPost(JSON.stringify(batch));
    if (r.ok) {
      totalSent += batch.length;
    } else if (!r.fatal) {
      // Transient — keep these events for next time.
      remaining.push(...batch);
    }
    // fatal (4xx) — drop, never going to succeed.
  }
  if (remaining.length === 0) {
    clearQueue();
  } else {
    try {
      writeFileSync(QUEUE_FILE(), remaining.map(JSON.stringify).join("\n") + "\n", { mode: 0o600 });
    } catch { /* nothing we can do */ }
  }
  return totalSent;
}

// ─── Public send API ─────────────────────────────────────────────

// Send a single event. Builds the envelope, attempts POST with
// retries, falls back to persistent queue on transient failure.
// Returns { sent: bool, reason?: string }. Never throws.
export async function sendEvent(opts) {
  if (telemetryDisabled({ flag: opts.disabled })) return { sent: false, reason: "disabled" };
  const envelope = buildEnvelope(opts);
  if (!envelope) return { sent: false, reason: "no_install_id" };
  const r = await httpPost(JSON.stringify(envelope));
  if (r.ok) return { sent: true, status: r.status, eventId: envelope.event_id };
  if (r.fatal) return { sent: false, reason: "rejected", status: r.status };
  // Transient — queue for next run
  appendToQueue(envelope);
  return { sent: false, reason: "queued" };
}

// ─── Legacy: existing callers use `send()` ───────────────────────
// Adapter so 0.6.x CLI code keeps working until callers are
// migrated. Maps old event names to v2 dotted names and forwards.

const V1_TO_V2 = {
  scan_complete: "scan.complete",
  redteam_complete: "redteam.complete",
  tripwire_decision: "tripwire.decision",
  tripwire_session_summary: "tripwire.session.end",
};

export async function send(opts) {
  const v2event = V1_TO_V2[opts.event] || opts.event;
  return sendEvent({ ...opts, event: v2event });
}

// ─── First-run notice ────────────────────────────────────────────

export function maybePrintFirstRunNotice({ tool, stream = process.stderr } = {}) {
  if (telemetryDisabled()) return;
  const noticeFile = join(decoyDir(), "telemetry-notice-shown");
  if (existsSync(noticeFile)) return;
  try {
    if (!existsSync(decoyDir())) mkdirSync(decoyDir(), { recursive: true });
    writeFileSync(noticeFile, new Date().toISOString() + "\n", { mode: 0o600 });
  } catch { /* non-fatal */ }
  stream.write(
    `${tool} reports anonymized usage to improve detections. ` +
    `Disable: DECOY_TELEMETRY=0 or --no-telemetry. Details: https://decoy.run/privacy\n`,
  );
}

// ─── Claim URL printing ──────────────────────────────────────────
// Printed at the end of a human-mode CLI run (not in JSON/SARIF
// output, not in CI). The URL lets the user click into a populated
// dashboard with this install's history.

export function maybePrintClaimURL({ tool, stream = process.stderr, force = false } = {}) {
  if (telemetryDisabled() && !force) return;
  // CI environments aren't going to click a link — skip.
  if (isCI()) return;
  let installId;
  try { installId = getOrCreateInstallId(); } catch { return; }
  if (!installId) return;
  const claimURL = `${API_BASE.replace(/\/api$/, "")}/d/${installId}`;
  const dashURL = claimURL.replace(/^http:\/\/localhost.*/, "https://app.decoy.run/d/" + installId);
  stream.write(`\n  See your dashboard: ${dashURL}\n`);
}

// ─── Tripwire batched decisions ──────────────────────────────────
// Buffer in memory; flush on size or interval. The tripwire process
// is long-running so memory buffering is fine. On SIGTERM/SIGINT we
// flush synchronously to disk so events aren't lost.

const _batch = [];
let _batchTimer = null;
const BATCH_MAX = 10;
const BATCH_INTERVAL_MS = 5000;

export function enqueueDecision(opts) {
  if (telemetryDisabled({ flag: opts.disabled })) return;
  const envelope = buildEnvelope(opts);
  if (!envelope) return;
  _batch.push(envelope);
  if (_batch.length >= BATCH_MAX) {
    flushBatch();
  } else if (!_batchTimer) {
    _batchTimer = setTimeout(flushBatch, BATCH_INTERVAL_MS);
  }
}

async function flushBatch() {
  if (_batchTimer) { clearTimeout(_batchTimer); _batchTimer = null; }
  if (_batch.length === 0) return;
  const drained = _batch.splice(0);
  const r = await httpPost(JSON.stringify(drained));
  if (!r.ok && !r.fatal) {
    // Transient — persist to queue. Next CLI run drains them.
    for (const e of drained) appendToQueue(e);
  }
}

// Synchronous flush — called on process exit signals. Best-effort:
// we drop batched events into the queue file so the next run picks
// them up. Can't await fetch from a sync exit handler.
export function flushBatchOnExit() {
  if (_batch.length === 0) return;
  for (const e of _batch) appendToQueue(e);
  _batch.length = 0;
  if (_batchTimer) { clearTimeout(_batchTimer); _batchTimer = null; }
}

// ─── Per-tool summarizers (kept here so CLI bin code stays small) ─


export function readInstallId() {
  return getOrCreateInstallId();
}

export function summarizeRedteamForTelemetry({ stories, coverage, servers, mode }) {
  const sevCounts = (stories || []).reduce((acc, s) => {
    acc[s.severity] = (acc[s.severity] || 0) + 1;
    return acc;
  }, {});
  const categoryCounts = (stories || []).reduce((acc, s) => {
    if (s.category) acc[s.category] = (acc[s.category] || 0) + 1;
    return acc;
  }, {});
  const owaspCounts = (stories || []).reduce((acc, s) => {
    if (s.owasp) acc[s.owasp] = (acc[s.owasp] || 0) + 1;
    return acc;
  }, {});
  return {
    timestamp: new Date().toISOString(),
    mode: mode || "default",
    serverCount: (servers || []).length,
    serverToolCounts: (servers || []).map(s => ({ tools: s.tools?.length || 0 })),
    coverage: coverage ? {
      executed: coverage.executed,
      total: coverage.total,
      percentage: coverage.percentage,
    } : null,
    stories: {
      total: (stories || []).length,
      bySeverity: sevCounts,
      byCategory: categoryCounts,
      byOwasp: owaspCounts,
    },
  };
}
