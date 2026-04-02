// Coverage calculation — honest assessment completeness percentage
//
// Layer 1: deterministic patterns actually executed
// Layer 2: estimated AI-adaptive + encoding variants (Guard Pro)
// Layer 3: estimated cross-server chains (Guard Pro)

import { ATTACKS, ENCODINGS } from "./attacks.mjs";

export function calculateCoverage(servers, executedCount) {
  const toolCount = servers.reduce((sum, s) => sum + (s.tools?.length || 0), 0);
  const serverCount = servers.filter(s => !s.error).length;

  // Layer 1: what we actually ran
  const l1 = executedCount;

  // Layer 2 estimate: for each tool with string params, estimate encoding variants + adaptive payloads
  let l2 = 0;
  const encodingCount = Object.keys(ENCODINGS).length;
  const injectionAttacks = ATTACKS.filter(a => a.category === "input-injection" && a.layer === 1);

  for (const server of servers) {
    if (server.error) continue;
    for (const tool of server.tools || []) {
      const props = tool.inputSchema?.properties || {};
      const stringParams = Object.values(props).filter(p => p.type === "string").length;

      // Each string param could get encoding variants of each injection type
      // But be conservative — not every injection applies to every param
      const applicableInjections = Math.min(injectionAttacks.length, 5);
      l2 += stringParams * applicableInjections * (encodingCount - 1); // -1 because one is the free taste

      // Adaptive payloads: ~3 per tool with complex schemas
      const hasComplexSchema = Object.keys(props).length >= 2;
      if (hasComplexSchema) l2 += 3;
    }
  }

  // Layer 3 estimate: cross-server chains
  // Conservative: (N choose 2) * average chain depth of 2
  let l3 = 0;
  if (serverCount >= 2) {
    const pairs = (serverCount * (serverCount - 1)) / 2;
    l3 = Math.round(pairs * toolCount * 0.3); // ~30% of tools participate in chains
  }

  const total = l1 + l2 + l3;
  const percentage = total > 0 ? Math.round((l1 / total) * 100) : 100;

  return {
    executed: l1,
    total,
    percentage,
    layer1: l1,
    layer2: l2,
    layer3: l3,
    serverCount,
    toolCount,
  };
}
