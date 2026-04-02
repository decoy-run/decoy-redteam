#!/usr/bin/env node

// Deliberately vulnerable MCP server for testing decoy-redteam
// This server has real vulnerabilities that the attack catalog should find.

import { createInterface } from "node:readline";

const SERVER_INFO = {
  name: "mock-vulnerable-server",
  version: "1.0.0",
};

const TOOLS = [
  {
    name: "execute_query",
    description: "Execute a SQL query against the database",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "SQL query to execute" },
      },
      required: ["query"],
    },
  },
  {
    name: "read_file",
    description: "Read a file from the filesystem",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Path to the file to read" },
      },
      required: ["path"],
    },
  },
  {
    name: "execute_command",
    description: "Execute a shell command",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command to run" },
      },
      required: ["command"],
    },
  },
  {
    name: "http_request",
    description: "Make an HTTP request to a URL",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL to request" },
        method: { type: "string", description: "HTTP method" },
      },
      required: ["url"],
    },
  },
  {
    name: "search_files",
    description: "Search for files matching a glob pattern",
    inputSchema: {
      type: "object",
      properties: {
        pattern: { type: "string", description: "Glob pattern to match" },
      },
      required: ["pattern"],
    },
  },
];

// Deliberately vulnerable responses
function handleToolCall(name, args) {
  switch (name) {
    case "execute_query": {
      const q = args?.query || "";
      // No sanitization — accepts anything
      if (q.includes("UNION")) {
        return { content: [{ type: "text", text: JSON.stringify({ rows: [{ table_name: "users" }, { table_name: "sessions" }] }) }] };
      }
      if (q.includes("pg_sleep") || q.includes("SLEEP") || q.includes("WAITFOR")) {
        // Return immediately but with timing metadata — the real delay would happen in production
        // Don't actually setTimeout here as it blocks subsequent request handling
        return { content: [{ type: "text", text: JSON.stringify({ rows: [], note: "query accepted and executed" }) }] };
      }
      if (q.includes("version()")) {
        return { content: [{ type: "text", text: "PostgreSQL 15.2" }] };
      }
      if (q.includes("current_user")) {
        return { content: [{ type: "text", text: "admin" }] };
      }
      // Default: accept query without error (vulnerable — no parameterization)
      return { content: [{ type: "text", text: JSON.stringify({ rows: [{ result: "ok" }], rowCount: 1 }) }] };
    }

    case "read_file": {
      const p = args?.path || "";
      // No path validation — accepts anything
      if (p.includes(".env")) {
        return { content: [{ type: "text", text: "DATABASE_URL=postgres://admin:s3cret@prod-db:5432/app\nSTRIPE_SECRET_KEY=sk_live_abc123\nAPI_KEY=tok_secret_xyz" }] };
      }
      if (p.includes("/etc/passwd")) {
        return { content: [{ type: "text", text: "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" }] };
      }
      if (p.includes(".git/config")) {
        return { content: [{ type: "text", text: "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:company/secret-repo.git" }] };
      }
      if (p.includes(".ssh")) {
        return { content: [{ type: "text", text: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..." }] };
      }
      // Accept any path
      return { content: [{ type: "text", text: `Contents of ${p}` }] };
    }

    case "execute_command": {
      const cmd = args?.command || "";
      // No sanitization — executes anything
      if (cmd.includes("whoami")) return { content: [{ type: "text", text: "root" }] };
      if (cmd.includes("id")) return { content: [{ type: "text", text: "uid=0(root) gid=0(root) groups=0(root)" }] };
      if (cmd.includes("/etc/passwd")) return { content: [{ type: "text", text: "root:x:0:0:root:/root:/bin/bash" }] };
      if (cmd.includes("/etc/hostname")) return { content: [{ type: "text", text: "prod-server-01" }] };
      return { content: [{ type: "text", text: `Executed: ${cmd}` }] };
    }

    case "http_request": {
      const url = args?.url || "";
      // No SSRF protection
      if (url.includes("169.254.169.254")) {
        return { content: [{ type: "text", text: JSON.stringify({ Code: "Success", AccessKeyId: "AKIA1234567890", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY" }) }] };
      }
      if (url.includes("127.0.0.1") || url.includes("localhost")) {
        return { content: [{ type: "text", text: "<html><body>Internal admin panel</body></html>" }] };
      }
      return { content: [{ type: "text", text: `Response from ${url}` }] };
    }

    case "search_files": {
      const pattern = args?.pattern || "";
      // No scope restriction
      if (pattern.includes("**")) {
        return { content: [{ type: "text", text: "/home/user/.env\n/home/user/.ssh/id_rsa\n/var/log/auth.log" }] };
      }
      return { content: [{ type: "text", text: `Results for ${pattern}` }] };
    }

    default:
      // Accept unknown tools (undeclared capabilities vulnerability)
      return { content: [{ type: "text", text: `Unknown tool: ${name}` }] };
  }
}

// ─── MCP stdio protocol ───

const rl = createInterface({ input: process.stdin, terminal: false });
let initialized = false;

rl.on("line", (line) => {
  if (!line.trim()) return;

  let msg;
  try {
    msg = JSON.parse(line.trim());
  } catch {
    return; // Ignore malformed JSON (but don't crash — this is itself a vulnerability)
  }

  // Handle initialize
  if (msg.method === "initialize") {
    respond(msg.id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    });
    initialized = true;
    return;
  }

  // Handle notifications (accept all — no rate limiting vulnerability)
  if (!msg.id) return;

  // Handle tools/list
  if (msg.method === "tools/list") {
    respond(msg.id, { tools: TOOLS });
    return;
  }

  // Handle tools/call
  if (msg.method === "tools/call") {
    const { name, arguments: args } = msg.params || {};
    const result = handleToolCall(name, args);

    respond(msg.id, result);
    return;
  }

  // Handle resources/list (responds even though not declared — vulnerability)
  if (msg.method === "resources/list") {
    respond(msg.id, { resources: [] });
    return;
  }

  // Handle prompts/list (responds even though not declared — vulnerability)
  if (msg.method === "prompts/list") {
    respond(msg.id, { prompts: [] });
    return;
  }

  // Handle logging/setLevel (responds even though not declared — vulnerability)
  if (msg.method === "logging/setLevel") {
    respond(msg.id, {});
    return;
  }

  // Accept anything else with invalid JSON-RPC version too
  if (msg.id) {
    respond(msg.id, { status: "ok" });
  }
});

function respond(id, result) {
  const msg = JSON.stringify({ jsonrpc: "2.0", id, result });
  process.stdout.write(msg + "\n");
}
