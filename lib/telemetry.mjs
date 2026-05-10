// Anonymous telemetry client for decoy-redteam.
//
// Mirror of decoy-scan/lib/telemetry.mjs minus the scan-specific summarizer;
// the redteam payload shape is added below as summarizeRedteamForTelemetry.
//
// Default: ON. Opt-out: DECOY_TELEMETRY=0 env var or `--no-telemetry` flag.
// First-run notice: single line, cached at ~/.decoy/telemetry-notice-shown.

import { writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { decoyDir, getOrCreateInstallId } from "./install_id.mjs";

const TELEMETRY_URL = process.env.DECOY_API_BASE
  ? `${process.env.DECOY_API_BASE.replace(/\/+$/, "")}/api/telemetry`
  : "https://app.decoy.run/api/telemetry";

const TIMEOUT_MS = 2000;

export function telemetryDisabled({ flag = false } = {}) {
  if (flag) return true;
  const env = String(process.env.DECOY_TELEMETRY ?? "").toLowerCase();
  return env === "0" || env === "false" || env === "off" || env === "no";
}

export function maybePrintFirstRunNotice({ tool, stream = process.stderr } = {}) {
  if (telemetryDisabled()) return;
  const noticeFile = join(decoyDir(), "telemetry-notice-shown");
  if (existsSync(noticeFile)) return;
  try {
    if (!existsSync(decoyDir())) mkdirSync(decoyDir(), { recursive: true });
    writeFileSync(noticeFile, new Date().toISOString() + "\n", { mode: 0o600 });
  } catch {
    // If we can't persist the marker, we'll print again next time. Not fatal.
  }
  stream.write(
    `${tool} reports anonymized findings to improve detections. ` +
    `Disable: DECOY_TELEMETRY=0 or --no-telemetry. Details: https://decoy.run/privacy\n`,
  );
}

export async function send({ tool, version, event, payload, disabled = false } = {}) {
  if (telemetryDisabled({ flag: disabled })) return { sent: false, reason: "disabled" };
  let installId;
  try { installId = getOrCreateInstallId(); }
  catch { return { sent: false, reason: "install_id_error" }; }

  const body = JSON.stringify({ tool, version, installId, event, payload: payload ?? null });
  try {
    const res = await fetch(TELEMETRY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    return { sent: true, status: res.status, installId };
  } catch (e) {
    return { sent: false, reason: "network", error: e.message };
  }
}

// Redteam-specific summarizer — counts and categories only, no story bodies
// (which can include exploit text the agent generated against the user's MCP
// server). Same conservative posture as the scan summarizer.
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
