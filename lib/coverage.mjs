// Coverage = what we ran against what we planned for this server set.
//
// Earlier versions reported a percentage against an invented "Layer 2/3"
// max (estimated AI-adaptive payloads + cross-server chains) so the
// upsell line could say "X% covered, paid would cover Y% more." Those
// totals were heuristic — string-param count × encoding count × pair
// count — and the percentage was a marketing artifact, not a fact about
// the run. The shape leaked into JSON/SARIF output. Removed.
//
// Now: `executed / planned`. No invented denominator. The Team/Business
// upsell is qualitative ("AI-adaptive attacks, encoding bypass,
// cross-server chains") rather than a fake delta.

export function calculateCoverage(servers, { executed, planned }) {
  const toolCount = servers.reduce((sum, s) => sum + (s.tools?.length || 0), 0);
  const serverCount = servers.filter(s => !s.error).length;

  const total = planned;
  const percentage = total > 0 ? Math.round((executed / total) * 100) : 100;

  return {
    executed,
    total,
    percentage,
    serverCount,
    toolCount,
  };
}
