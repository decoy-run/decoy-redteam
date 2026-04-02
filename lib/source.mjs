// Source code extraction — read MCP server implementation from disk or GitHub
//
// Two modes:
// 1. Local: given an MCP config entry, resolve and read server source from disk/node_modules
// 2. GitHub: given a repo URL, fetch source via GitHub API (Pro feature)
//
// This enables source-code-assisted red teaming: find vulnerabilities in the actual
// implementation, not just probe the API surface.

import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, dirname, join, extname } from "node:path";

const MAX_FILE_SIZE = 100_000;  // 100KB per file — skip minified bundles
const MAX_TOTAL_SIZE = 300_000; // 300KB total — keep LLM costs under control
const MAX_FILES = 20;           // Don't read entire node_modules

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "__pycache__", ".next"]);
const CODE_EXTS = new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".py"]);

/**
 * Extract source code from an MCP server config entry.
 * Returns { entryPoint, files: [{ path, content, lines }], totalLines, truncated }
 */
export function extractSource(entry) {
  const entryPoint = resolveEntryPoint(entry);
  if (!entryPoint) return null;

  const files = [];
  let totalSize = 0;
  const visited = new Set();

  // Start from the entry point and follow local imports
  const queue = [entryPoint];

  while (queue.length > 0 && files.length < MAX_FILES) {
    const filePath = queue.shift();
    if (visited.has(filePath)) continue;
    visited.add(filePath);

    const content = readSafe(filePath);
    if (!content) continue;

    if (totalSize + content.length > MAX_TOTAL_SIZE) {
      return { entryPoint, files, totalLines: files.reduce((s, f) => s + f.lines, 0), truncated: true };
    }

    const lines = content.split("\n").length;
    files.push({ path: filePath, content, lines });
    totalSize += content.length;

    // Follow local imports (not npm packages)
    const imports = extractImports(content, dirname(filePath));
    for (const imp of imports) {
      if (!visited.has(imp)) queue.push(imp);
    }
  }

  return {
    entryPoint,
    files,
    totalLines: files.reduce((s, f) => s + f.lines, 0),
    truncated: files.length >= MAX_FILES,
  };
}

/**
 * Resolve the server entry point from config entry.
 * Handles: node path/to/server.mjs, npx package-name, python script.py
 */
function resolveEntryPoint(entry) {
  const cmd = entry.command;
  const args = entry.args || [];

  // node /path/to/file.js
  if (cmd === "node" || cmd === "node.exe") {
    const scriptArg = args.find(a => !a.startsWith("-") && (a.endsWith(".js") || a.endsWith(".mjs") || a.endsWith(".cjs")));
    if (scriptArg) {
      const resolved = resolve(scriptArg);
      if (existsSync(resolved)) return resolved;
    }
  }

  // npx package-name → look in node_modules
  if (cmd === "npx") {
    const pkg = args.find(a => !a.startsWith("-") && a !== "-y");
    if (pkg) {
      // Try to find the package's main file in common locations
      const candidates = [
        join(process.cwd(), "node_modules", pkg, "index.mjs"),
        join(process.cwd(), "node_modules", pkg, "index.js"),
        join(process.cwd(), "node_modules", pkg, "dist", "index.js"),
      ];
      for (const c of candidates) {
        if (existsSync(c)) return c;
      }
      // Try to resolve via package.json bin field
      const pkgJsonPath = join(process.cwd(), "node_modules", pkg, "package.json");
      if (existsSync(pkgJsonPath)) {
        try {
          const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
          const bin = typeof pkgJson.bin === "string" ? pkgJson.bin : Object.values(pkgJson.bin || {})[0];
          if (bin) {
            const binPath = resolve(dirname(pkgJsonPath), bin);
            if (existsSync(binPath)) return binPath;
          }
          const main = pkgJson.main || pkgJson.module;
          if (main) {
            const mainPath = resolve(dirname(pkgJsonPath), main);
            if (existsSync(mainPath)) return mainPath;
          }
        } catch {}
      }
    }
  }

  // python/python3 script.py
  if (cmd === "python" || cmd === "python3" || cmd === "python.exe") {
    const scriptArg = args.find(a => !a.startsWith("-") && a.endsWith(".py"));
    if (scriptArg) {
      const resolved = resolve(scriptArg);
      if (existsSync(resolved)) return resolved;
    }
  }

  // Direct script path as command
  if (existsSync(resolve(cmd)) && CODE_EXTS.has(extname(cmd))) {
    return resolve(cmd);
  }

  return null;
}

/**
 * Read a file safely, respecting size limits and skipping binaries.
 */
function readSafe(filePath) {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) return null;
    if (!stat.isFile()) return null;

    const ext = extname(filePath);
    if (!CODE_EXTS.has(ext)) return null;

    const content = readFileSync(filePath, "utf8");

    // Skip minified files (single very long line)
    const firstNewline = content.indexOf("\n");
    if (firstNewline > 5000 || (firstNewline === -1 && content.length > 5000)) return null;

    return content;
  } catch {
    return null;
  }
}

/**
 * Extract local import paths from source code.
 * Follows relative imports only (./foo, ../bar), not npm packages.
 */
function extractImports(content, baseDir) {
  const imports = [];
  // ES module: import ... from "./path"
  // CommonJS: require("./path")
  const patterns = [
    /import\s+.*?\s+from\s+["'](\.[^"']+)["']/g,
    /import\s*\(\s*["'](\.[^"']+)["']\s*\)/g,
    /require\s*\(\s*["'](\.[^"']+)["']\s*\)/g,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const importPath = match[1];
      const resolved = resolveImport(importPath, baseDir);
      if (resolved) imports.push(resolved);
    }
  }

  return imports;
}

/**
 * Resolve an import path to an actual file.
 * Tries: exact path, .js, .mjs, .ts, /index.js, /index.mjs
 */
function resolveImport(importPath, baseDir) {
  const base = resolve(baseDir, importPath);

  // Exact match
  if (existsSync(base) && statSync(base).isFile()) return base;

  // Try extensions
  for (const ext of [".js", ".mjs", ".cjs", ".ts", ".mts"]) {
    const withExt = base + ext;
    if (existsSync(withExt)) return withExt;
  }

  // Try index files
  for (const idx of ["index.js", "index.mjs", "index.ts"]) {
    const withIdx = join(base, idx);
    if (existsSync(withIdx)) return withIdx;
  }

  return null;
}

// ─── GitHub Source Extraction (Pro) ───

/**
 * Fetch source code from a GitHub repository.
 * Accepts: "owner/repo", "github.com/owner/repo", full URL
 * Uses GitHub API (no auth required for public repos, GITHUB_TOKEN for private)
 *
 * Returns same shape as extractSource: { entryPoint, files, totalLines, truncated }
 */
export async function extractGitHubSource(repoRef, { subdir, token } = {}) {
  const { owner, repo } = parseGitHubRef(repoRef);
  if (!owner || !repo) return null;

  const headers = { "Accept": "application/vnd.github.v3+json", "User-Agent": "decoy-redteam" };
  if (token) headers["Authorization"] = `token ${token}`;

  // Get the repo tree recursively
  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`;
  const treeRes = await fetch(treeUrl, { headers });
  if (!treeRes.ok) {
    const err = await treeRes.json().catch(() => ({}));
    throw new Error(`GitHub API: ${err.message || treeRes.status}`);
  }

  const treeData = await treeRes.json();
  const tree = treeData.tree || [];

  // Filter to source files in the target subdirectory
  const prefix = subdir ? subdir.replace(/^\/|\/$/g, "") + "/" : "";
  const sourceFiles = tree.filter(f => {
    if (f.type !== "blob") return false;
    if (prefix && !f.path.startsWith(prefix)) return false;
    const ext = extname(f.path);
    if (!CODE_EXTS.has(ext)) return false;
    // Skip test files, configs, and obvious non-server files
    if (/\/(test|__test__|spec|__mocks__|\.github|docs)\//i.test(f.path)) return false;
    if (f.size > MAX_FILE_SIZE) return false;
    return true;
  });

  // Fetch file contents (respect limits)
  const files = [];
  let totalSize = 0;

  for (const entry of sourceFiles) {
    if (files.length >= MAX_FILES) break;
    if (totalSize + entry.size > MAX_TOTAL_SIZE) break;

    const blobUrl = `https://api.github.com/repos/${owner}/${repo}/git/blobs/${entry.sha}`;
    const blobRes = await fetch(blobUrl, { headers });
    if (!blobRes.ok) continue;

    const blobData = await blobRes.json();
    const content = Buffer.from(blobData.content, "base64").toString("utf8");

    // Skip minified
    const firstNewline = content.indexOf("\n");
    if (firstNewline > 5000 || (firstNewline === -1 && content.length > 5000)) continue;

    const lines = content.split("\n").length;
    files.push({ path: entry.path, content, lines });
    totalSize += content.length;
  }

  return {
    entryPoint: `github.com/${owner}/${repo}${subdir ? "/" + subdir : ""}`,
    files,
    totalLines: files.reduce((s, f) => s + f.lines, 0),
    truncated: files.length >= MAX_FILES || totalSize >= MAX_TOTAL_SIZE,
    source: "github",
  };
}

function parseGitHubRef(ref) {
  // "owner/repo"
  const simple = ref.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (simple) return { owner: simple[1], repo: simple[2] };

  // "github.com/owner/repo" or "https://github.com/owner/repo"
  const url = ref.match(/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/);
  if (url) return { owner: url[1], repo: url[2] };

  return { owner: null, repo: null };
}
