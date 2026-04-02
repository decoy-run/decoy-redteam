// Report generation — terminal output, JSON, SARIF

// ─── SARIF 2.1.0 ───

export function toSarif(stories, coverage, meta) {
  const rules = [];
  const results = [];

  for (const story of stories) {
    const ruleId = `decoy-redteam-${story.attackId}`;
    const ruleIdx = rules.length;

    rules.push({
      id: ruleId,
      shortDescription: { text: story.title },
      fullDescription: { text: story.impact },
      defaultConfiguration: {
        level: story.severity === "critical" || story.severity === "high" ? "error"
          : story.severity === "medium" ? "warning" : "note",
      },
      properties: {
        tags: [story.owasp, story.ascf].filter(Boolean),
      },
    });

    results.push({
      ruleId,
      ruleIndex: ruleIdx,
      level: story.severity === "critical" || story.severity === "high" ? "error"
        : story.severity === "medium" ? "warning" : "note",
      message: {
        text: `${story.title}\n\nImpact: ${story.impact}\n\nRemediation: ${story.remediation}`,
      },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: `mcp-server://${encodeURIComponent(story.server)}` },
        },
      }],
      properties: {
        severity: story.severity,
        category: story.category,
        tool: story.tool,
        owasp: story.owasp,
        ascf: story.ascf,
      },
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "decoy-redteam",
          version: meta.version,
          informationUri: "https://decoy.run",
          rules,
        },
      },
      results,
    }],
  };
}

// ─── JSON output ───

export function toJson(stories, coverage, meta) {
  return {
    timestamp: new Date().toISOString(),
    version: meta.version,
    mode: meta.mode,
    servers: meta.servers,
    tools: meta.tools,
    stories,
    coverage,
    summary: {
      critical: stories.filter(s => s.severity === "critical").length,
      high: stories.filter(s => s.severity === "high").length,
      medium: stories.filter(s => s.severity === "medium").length,
      low: stories.filter(s => s.severity === "low").length,
      total: stories.length,
    },
  };
}
