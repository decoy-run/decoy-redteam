// MCP stdio transport — persistent connections with tools/call support

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const TIMEOUT = 15_000;
const __dirname = dirname(fileURLToPath(import.meta.url));
const PKG_VERSION = (() => { try { return JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8")).version; } catch { return "0.0.0"; } })();
const CLIENT_INFO = { name: "decoy-redteam", version: PKG_VERSION };

export class McpConnection {
  #proc = null;
  #buffer = "";
  #pending = new Map(); // id → { resolve, timer }
  #nextId = 10;
  #name;
  #entry;
  #tools = [];
  #connected = false;
  #stderr = "";

  constructor(name, entry) {
    this.#name = name;
    this.#entry = entry;
  }

  get name() { return this.#name; }
  get tools() { return this.#tools; }
  get connected() { return this.#connected; }

  async connect() {
    // Kill existing process if reconnecting
    if (this.#proc) {
      try { this.#proc.kill(); } catch {}
      this.#proc = null;
    }

    const { command, args = [], env: serverEnv = {} } = this.#entry;
    const mergedEnv = { ...process.env, ...serverEnv };

    this.#proc = spawn(command, args, {
      env: mergedEnv,
      stdio: ["pipe", "pipe", "pipe"],
    });

    this.#proc.stdout.on("data", (chunk) => this.#onData(chunk));
    this.#proc.stderr?.on("data", (chunk) => {
      this.#stderr += chunk.toString();
      if (this.#stderr.length > 4096) this.#stderr = this.#stderr.slice(-4096);
    });
    this.#proc.on("error", (e) => { this.#connected = false; this.#rejectAll(e.message); });
    this.#proc.on("exit", () => {
      this.#connected = false;
      const hint = this.#stderr.trim().split("\n").pop()?.slice(0, 200) || "";
      this.#rejectAll(hint ? `Process exited: ${hint}` : "Process exited");
    });

    // Initialize handshake
    const initResult = await this.#send("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: CLIENT_INFO,
    });

    if (!initResult?.capabilities) {
      throw new Error(`${this.#name}: initialize failed`);
    }

    // Send initialized notification
    this.#write({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

    // Get tools
    const listResult = await this.#send("tools/list", {});
    this.#tools = listResult?.tools || [];
    this.#connected = true;
    return this.#tools;
  }

  async callTool(toolName, args = {}) {
    if (!this.#connected) throw new Error("Not connected");
    const start = performance.now();
    try {
      const result = await this.#send("tools/call", { name: toolName, arguments: args });
      const elapsed = performance.now() - start;
      // MCP error responses come back as { _mcpError: true, error: {...} }
      if (result?._mcpError) {
        return { result: null, error: result.error, elapsed };
      }
      return { result, error: null, elapsed };
    } catch (e) {
      const elapsed = performance.now() - start;
      return { result: null, error: e.message, elapsed };
    }
  }

  async sendRaw(jsonString, { timeout = 1000 } = {}) {
    if (!this.#proc) throw new Error("Not connected");

    // Size limit: reject payloads over 1MB to prevent abuse
    const MAX_RAW_SIZE = 1_048_576; // 1MB
    if (jsonString.length > MAX_RAW_SIZE) {
      throw new Error(`Payload exceeds maximum size (${jsonString.length} > ${MAX_RAW_SIZE} bytes)`);
    }

    const start = performance.now();
    try {
      // Parse to check if this has an id we should wait for
      let expectId = null;
      try {
        const parsed = JSON.parse(jsonString.split("\n")[0]);
        expectId = parsed.id;
      } catch {}

      if (expectId != null) {
        // Register the pending handler BEFORE writing to stdin,
        // so a fast response isn't dropped by #onData.
        const result = await new Promise((resolve) => {
          const timer = setTimeout(() => {
            this.#pending.delete(expectId);
            resolve({ error: { code: -1, message: "Timeout" } });
          }, timeout);
          this.#pending.set(expectId, { resolve, reject: () => resolve({ error: { code: -1, message: "Timeout" } }), timer });
          this.#proc.stdin.write(jsonString + "\n");
        });
        // Unwrap timeout error responses
        if (result?.error?.code === -1) {
          return { result: null, error: result.error, elapsed: performance.now() - start };
        }
        return { result, error: null, elapsed: performance.now() - start };
      }

      // No ID (notification) — just fire and forget with short delay
      this.#proc.stdin.write(jsonString + "\n");
      await new Promise(r => setTimeout(r, Math.min(timeout, 100)));
      return { result: null, error: null, elapsed: performance.now() - start };
    } catch (e) {
      return { result: null, error: e.message, elapsed: performance.now() - start };
    }
  }

  close() {
    this.#connected = false;
    this.#rejectAll("Connection closed");
    if (this.#proc) {
      try { this.#proc.kill(); } catch {}
      this.#proc = null;
    }
  }

  // --- private ---

  #send(method, params) {
    return new Promise((resolve, reject) => {
      const id = this.#nextId++;
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`Timeout waiting for ${method}`));
      }, TIMEOUT);

      this.#pending.set(id, { resolve, reject, timer });
      this.#write({ jsonrpc: "2.0", id, method, params });
    });
  }

  #write(msg) {
    if (!this.#proc?.stdin?.writable) throw new Error("stdin not writable");
    this.#proc.stdin.write(JSON.stringify(msg) + "\n");
  }

  #onData(chunk) {
    this.#buffer += chunk.toString();
    const lines = this.#buffer.split("\n");
    // Keep incomplete last line in buffer
    this.#buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line.trim());
        if (msg.id != null && this.#pending.has(msg.id)) {
          const { resolve, timer } = this.#pending.get(msg.id);
          clearTimeout(timer);
          this.#pending.delete(msg.id);
          if (msg.error) {
            resolve({ _mcpError: true, error: msg.error });
          } else {
            resolve(msg.result);
          }
        }
      } catch {
        // Malformed JSON-RPC message from server — skip it
      }
    }
  }

  #rejectAll(reason) {
    for (const [id, { reject, timer }] of this.#pending) {
      clearTimeout(timer);
      reject(new Error(reason));
    }
    this.#pending.clear();
  }
}
