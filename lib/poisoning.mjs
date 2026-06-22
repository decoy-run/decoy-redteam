// Tool-surface poisoning detection — passive (no payloads sent).
//
// An MCP server advertises each tool with a name, a description, and a JSON
// schema. Those strings are fed to the agent's model verbatim, so a malicious
// or compromised server can smuggle instructions there to hijack the agent —
// "tool poisoning." Unlike a payload attack, this is detectable just by reading
// the tool surface the server *actually serves at runtime*, which is why it
// belongs to the red-team connect step and runs even in dry-run. It's the
// runtime complement to decoy-scan's static check: scan inspects what you
// installed; this inspects what the server hands the model right now (catching
// rug-pulls and servers whose served metadata differs from their manifest).
//
// Precision bar matches the rest of the catalog: each signature anchors on a
// structurally distinctive shape that honest tool docs effectively never carry.
// We deliberately avoid generic imperatives ("use this to…", "always provide a
// valid path") — only agent-directed manipulation fires.

// Invisible/format characters that render as nothing to a human but reach the
// model: zero-width & bidi (U+200B–200F, 202A–202E, 2060–2064, 206A–206F),
// BOM/ZWNBSP (FEFF), interlinear annotation (FFF9–FFFB), and the Tags block
// (U+E0000–E007F) used for steganographic instruction smuggling.
const INVISIBLE = /[​-‏‪-‮⁠-⁤⁪-⁯﻿￹-￻]|[\u{e0000}-\u{e007f}]/u;

// ─── Signatures ───

const SIGNATURES = [
  {
    id: "TPA-001", subcategory: "instruction-override",
    severity: "critical", owasp: "ASI01", ascf: "ASCF-07",
    title: "Tool poisoning — instruction override in tool metadata",
    // "ignore/disregard/forget … previous/your/the system … instructions" — the
    // classic override aimed at the model. Requires the directive object
    // (instructions/prompt/rules), so "ignore case" / "ignore all errors" don't fire.
    test: (t) => t.match(/\b(?:ignore|disregard|forget|override|bypass)\b[^.?!\n]{0,40}\b(?:previous|prior|above|earlier|all|your|the system|original)\b[^.?!\n]{0,24}\b(?:instruction|prompt|rule|direction|guideline|context)s?\b/i),
    impact: "The tool's description tells the agent to discard its own instructions. A model that reads this tool list can be steered off its task before any tool is even called.",
    remediation: "Do not connect this server. Tool descriptions are model-visible text — treat a server that injects instructions there as hostile and remove it.",
  },
  {
    id: "TPA-002", subcategory: "concealment",
    severity: "critical", owasp: "ASI01", ascf: "ASCF-07",
    title: "Tool poisoning — instruction to hide actions from the user",
    // "do not tell the user" / "without informing the operator" — concealment
    // directives. The object must be the human (user/operator/owner), so
    // "do not pass secrets" does not fire.
    test: (t) =>
      t.match(/\b(?:do not|don'?t|never|avoid)\b[^.?!\n]{0,30}\b(?:tell|inform|notify|alert|reveal|mention|show|disclose|warn|let)\b[^.?!\n]{0,30}\b(?:user|human|operator|owner|person)\b/i)
      || t.match(/\bwithout\b[^.?!\n]{0,24}\b(?:telling|informing|alerting|notifying|asking)\b[^.?!\n]{0,24}\b(?:user|human|operator|owner)\b/i),
    impact: "The tool's description instructs the agent to act behind the user's back. Combined with any data or side-effect tool, this is covert exfiltration or unauthorized action.",
    remediation: "Do not connect this server. A tool that asks the agent to conceal its behavior from the operator is hostile by definition.",
  },
  {
    id: "TPA-003", subcategory: "exfiltration",
    severity: "critical", owasp: "ASI06", ascf: "ASCF-04",
    title: "Tool poisoning — embedded data-exfiltration instruction",
    // An exfil verb + an external destination + a sensitive object. All three
    // are required, so a legit "posts a message to a Slack webhook" (no
    // sensitive object) does not fire.
    test: (t) => {
      // verb … external destination, within one clause. The gap allows dots so
      // it can span dotted paths/URLs (e.g. "~/.aws/credentials to https://…").
      const exfilToHost = /\b(?:send|post|forward|upload|transmit|exfiltrate|leak|copy|email|deliver)\b[^\n]{0,80}(?:https?:\/\/|[\w-]+\.[a-z]{2,}\/|attacker[\w.-]*\/|evil[\w.-]*\/|webhook\.site|pastebin|requestbin|burpcollab|ngrok|interactsh)/i;
      const sensitive = /\b(?:api[_\s-]?key|access[_\s-]?key|secret|credential|token|password|passwd|private key|\.env|\.ssh|\.aws|environment variable|contents? of|the file)\b/i;
      return exfilToHost.test(t) && sensitive.test(t) ? t.match(exfilToHost) : null;
    },
    impact: "The tool's description hard-codes an instruction to ship sensitive data to an external endpoint. The agent has no way to distinguish this from a legitimate step.",
    remediation: "Do not connect this server. Report the package — an embedded exfiltration instruction is an active backdoor, not a misconfiguration.",
  },
  {
    id: "TPA-004", subcategory: "hidden-directive",
    severity: "high", owasp: "ASI01", ascf: "ASCF-07",
    title: "Tool poisoning — fake system framing or tool-precedence priming",
    // Fake authority markup (`<IMPORTANT>`, `<system>`), impersonated control
    // phrases ("you are now", "system prompt", "maintenance mode", "new task:"),
    // or a description demanding precedence over "any other tool" (the tell:
    // honest init docs reference *this* tool, not *any other* tool).
    test: (t) =>
      t.match(/<\/?(?:important|system|secret|instructions?|admin|assistant)\s*>|\[\[(?:system|important|instructions?)\]\]/i)
      || t.match(/\b(?:system prompt|you are now|new task\s*:|maintenance mode|developer mode|as an ai|the assistant must)\b/i)
      || t.match(/\bbefore\b[^.?!\n]{0,30}\b(?:any other|every other|all other|each other)\b[^.?!\n]{0,16}\btools?\b/i),
    impact: "The tool's description impersonates a system message or inserts itself ahead of every other tool. Models give such framing elevated trust, so it reliably biases tool selection and behavior.",
    remediation: "Do not connect this server. Tool descriptions are data, not control text — a server that formats them as system instructions is attempting to manipulate the model.",
  },
  {
    id: "TPA-005", subcategory: "hidden-unicode",
    severity: "high", owasp: "ASI01", ascf: "ASCF-07",
    title: "Tool poisoning — invisible characters in tool metadata",
    // Zero-width, bidi-override, and Unicode Tags-block characters render as
    // nothing to a human reviewer but reach the model. They're used to hide a
    // second set of instructions inside an innocuous-looking description.
    test: (t) => t.match(INVISIBLE),
    impact: "The tool's metadata contains characters invisible to a human reading the description but visible to the model — the standard way a benign-looking tool smuggles hidden instructions past review.",
    remediation: "Do not connect this server. Strip and inspect the raw bytes of the tool description; legitimate tools have no reason to embed invisible control characters.",
  },
];

// ─── Tool surface walk ───

// Collect every model-visible string a tool advertises: its name, description,
// and the human-text fields of its input schema (param descriptions, titles,
// enum values, defaults). These are exactly the strings handed to the model.
function collectTextFields(tool) {
  const fields = [];
  if (tool.name) fields.push({ path: "name", text: String(tool.name) });
  if (tool.description) fields.push({ path: "description", text: String(tool.description) });

  const schema = tool.inputSchema || tool.input_schema;
  walkSchema(schema, "inputSchema", fields);
  return fields;
}

function walkSchema(node, path, fields, depth = 0) {
  if (!node || typeof node !== "object" || depth > 8) return;
  for (const key of ["description", "title"]) {
    if (typeof node[key] === "string" && node[key]) {
      fields.push({ path: `${path}.${key}`, text: node[key] });
    }
  }
  if (typeof node.default === "string" && node.default) {
    fields.push({ path: `${path}.default`, text: node.default });
  }
  if (Array.isArray(node.enum)) {
    for (const v of node.enum) {
      if (typeof v === "string" && v) fields.push({ path: `${path}.enum`, text: v });
    }
  }
  const props = node.properties;
  if (props && typeof props === "object") {
    for (const [name, child] of Object.entries(props)) {
      walkSchema(child, `${path}.${name}`, fields, depth + 1);
    }
  }
  if (node.items) walkSchema(node.items, `${path}.items`, fields, depth + 1);
}

// ─── Evidence rendering ───

// Show the offending text with a little surrounding context. Invisible
// characters (the TPA-005 case) are made visible as ‹U+XXXX› so the evidence is
// actually readable in terminal output and screenshots.
function excerpt(text, match) {
  const at = typeof match.index === "number" ? match.index : 0;
  const start = Math.max(0, at - 24);
  const end = Math.min(text.length, at + (match[0]?.length || 0) + 24);
  let slice = (start > 0 ? "…" : "") + text.slice(start, end) + (end < text.length ? "…" : "");
  slice = slice.replace(new RegExp(INVISIBLE, "gu"),
    (ch) => `‹U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}›`);
  return slice;
}

function toStory(sig, server, tool, field, match, idx) {
  return {
    id: `POISON-${String(idx).padStart(3, "0")}`,
    severity: sig.severity,
    confidence: "high",
    category: "tool-poisoning",
    subcategory: sig.subcategory,
    title: sig.title,
    impact: sig.impact,
    remediation: sig.remediation,
    owasp: sig.owasp,
    ascf: sig.ascf,
    server: server.name,
    tool: tool.name,
    attackId: sig.id,
    layer: 1,
    encodingVariant: null,
    passive: true,
    evidence: [{
      payload: field.path,
      outcome: "vulnerable",
      elapsed: 0,
      response: excerpt(field.text, match),
    }],
  };
}

// ─── Public API ───

// Inspect the advertised tool surface of every connected server. Returns
// findings in the same shape buildStories() produces, so they flow through the
// existing JSON / SARIF / terminal / exit-code paths unchanged.
export function detectToolPoisoning(servers) {
  const stories = [];
  let idx = 1;
  for (const server of servers || []) {
    if (server.error || !server.conn) continue;
    for (const tool of server.tools || []) {
      const fields = collectTextFields(tool);
      const fired = new Set(); // one finding per (tool, signature)
      for (const sig of SIGNATURES) {
        if (fired.has(sig.id)) continue;
        for (const field of fields) {
          const match = sig.test(field.text);
          if (match) {
            fired.add(sig.id);
            stories.push(toStory(sig, server, tool, field, match, idx++));
            break;
          }
        }
      }
    }
  }
  // Surface critical findings first, consistent with buildStories ordering.
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  stories.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));
  return stories;
}

export const POISONING_SIGNATURES = SIGNATURES;
