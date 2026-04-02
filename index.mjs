// decoy-redteam — autonomous red team for MCP servers

export { ATTACKS, ENCODINGS, matchAttacks, getEncodingTaste } from "./lib/attacks.mjs";
export { McpConnection } from "./lib/transport.mjs";
export { discoverConfigs, probeServers, planAttacks, executeAttacks, buildStories, closeAll } from "./lib/engine.mjs";
export { calculateCoverage } from "./lib/coverage.mjs";
export { toSarif, toJson } from "./lib/report.mjs";
export { extractSource, extractGitHubSource } from "./lib/source.mjs";
