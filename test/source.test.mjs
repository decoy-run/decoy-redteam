import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { extractSource } from "../lib/source.mjs";

const TMP = join(tmpdir(), `decoy-source-test-${Date.now()}`);

before(() => mkdirSync(TMP, { recursive: true }));
after(() => rmSync(TMP, { recursive: true, force: true }));

describe("extractSource", () => {
  it("reads a simple JS file", () => {
    const file = join(TMP, "simple.mjs");
    writeFileSync(file, 'console.log("hello");\n');

    const result = extractSource({ command: "node", args: [file] });
    assert.ok(result, "should return a result");
    assert.equal(result.entryPoint, file);
    assert.equal(result.files.length, 1);
    assert.equal(result.files[0].path, file);
    assert.ok(result.files[0].content.includes("hello"));
    assert.equal(result.truncated, false);
  });

  it("follows local imports", () => {
    const dir = join(TMP, "imports");
    mkdirSync(dir, { recursive: true });

    const helperFile = join(dir, "helper.mjs");
    writeFileSync(helperFile, 'export const x = 1;\n');

    const entryFile = join(dir, "entry.mjs");
    writeFileSync(entryFile, 'import { x } from "./helper.mjs";\nconsole.log(x);\n');

    const result = extractSource({ command: "node", args: [entryFile] });
    assert.ok(result);
    assert.equal(result.files.length, 2);
    const paths = result.files.map(f => f.path);
    assert.ok(paths.includes(entryFile));
    assert.ok(paths.includes(helperFile));
  });

  it("respects MAX_FILES limit", () => {
    const dir = join(TMP, "many-files");
    mkdirSync(dir, { recursive: true });

    // Create 25 files, each importing the next
    for (let i = 0; i < 25; i++) {
      const imp = i < 24 ? `import { v${i + 1} } from "./f${i + 1}.mjs";\n` : "";
      writeFileSync(join(dir, `f${i}.mjs`), `${imp}export const v${i} = ${i};\n`);
    }

    const result = extractSource({ command: "node", args: [join(dir, "f0.mjs")] });
    assert.ok(result);
    assert.ok(result.files.length <= 20, `Should cap at MAX_FILES (20), got ${result.files.length}`);
    assert.equal(result.truncated, true);
  });

  it("returns null for non-existent path", () => {
    const result = extractSource({ command: "node", args: ["/tmp/does-not-exist-12345.mjs"] });
    assert.equal(result, null);
  });

  it("returns null for unrecognized command", () => {
    const result = extractSource({ command: "some-random-binary", args: [] });
    assert.equal(result, null);
  });
});

describe("resolveEntryPoint (via extractSource)", () => {
  it("resolves python scripts", () => {
    const file = join(TMP, "server.py");
    writeFileSync(file, 'print("hello")\n');

    // extractSource returns null because .py content is read but python entry is resolved
    const result = extractSource({ command: "python3", args: [file] });
    assert.ok(result, "should resolve python entry point");
    assert.equal(result.entryPoint, file);
  });

  it("resolves direct script path as command", () => {
    const file = join(TMP, "direct.mjs");
    writeFileSync(file, 'console.log("direct");\n');

    const result = extractSource({ command: file, args: [] });
    assert.ok(result);
    assert.equal(result.entryPoint, file);
  });

  it("handles node command with flags before script", () => {
    const file = join(TMP, "flagged.js");
    writeFileSync(file, "module.exports = {};\n");

    const result = extractSource({ command: "node", args: ["--experimental-modules", file] });
    assert.ok(result);
    assert.equal(result.entryPoint, file);
  });
});
