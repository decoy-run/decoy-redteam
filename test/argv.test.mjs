// Tests for the shared CLI argument-hygiene helpers.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EXIT_USAGE,
  editDistance,
  nearest,
  findUnknownFlag,
  resolveColor,
} from "../lib/argv.mjs";

describe("editDistance", () => {
  it("is zero for identical strings", () => {
    assert.equal(editDistance("json", "json"), 0);
  });

  it("counts an adjacent transposition as one edit", () => {
    // Plain Levenshtein scores this 2, which is far enough to suppress the
    // suggestion for a four-letter flag — exactly when it is most wanted.
    assert.equal(editDistance("josn", "json"), 1);
  });

  it("counts a substitution, insertion and deletion as one edit each", () => {
    assert.equal(editDistance("jsom", "json"), 1);
    assert.equal(editDistance("jsonn", "json"), 1);
    assert.equal(editDistance("jso", "json"), 1);
  });

  it("handles empty strings", () => {
    assert.equal(editDistance("", "json"), 4);
    assert.equal(editDistance("json", ""), 4);
  });
});

describe("nearest", () => {
  const flags = ["json", "sarif", "brief", "no-probe", "no-telemetry", "verbose"];

  it("finds a one-edit match", () => {
    assert.equal(nearest("jsom", flags), "json");
  });

  it("treats an abbreviation as a prefix match, not a near-miss", () => {
    // "crit" is four edits from "critical" but is plainly reaching for it.
    assert.equal(nearest("crit", ["critical", "high"]), "critical");
  });

  it("prefers the shortest candidate a prefix matches", () => {
    assert.equal(nearest("no-", ["no-probe", "no-telemetry"]), "no-probe");
  });

  it("returns null when nothing is close", () => {
    assert.equal(nearest("xyzzy", flags), null);
  });

  it("does not suggest the input itself", () => {
    assert.equal(nearest("json", ["json"]), "json");
  });

  it("scales tolerance with length rather than allowing wild guesses", () => {
    // Four letters, two edits away — too far to guess at.
    assert.equal(nearest("abcd", ["json"]), null);
  });
});

describe("findUnknownFlag", () => {
  const known = new Set(["json", "quiet", "q", "token"]);

  it("returns null when every flag is known", () => {
    assert.equal(findUnknownFlag(["--json", "-q", "--token=abc"], known), null);
  });

  it("reports the first unknown flag", () => {
    assert.deepEqual(
      findUnknownFlag(["--json", "--nope", "--alsonope"], known),
      { arg: "--nope", name: "nope" },
    );
  });

  it("matches a --name=value flag on its name", () => {
    assert.equal(findUnknownFlag(["--token=secret"], known), null);
  });

  it("ignores positionals and a bare dash", () => {
    assert.equal(findUnknownFlag(["explain", "critical", "-"], known), null);
  });

  it("stops at a bare -- so upstream flags are never inspected", () => {
    assert.equal(findUnknownFlag(["--json", "--", "--upstream-only"], known), null);
  });
});

describe("resolveColor", () => {
  const tty = { isTTY: true };
  const pipe = { isTTY: false };

  function withEnv(env, fn) {
    const saved = {};
    for (const k of ["NO_COLOR", "FORCE_COLOR", "TERM"]) {
      saved[k] = process.env[k];
      if (env[k] === undefined) delete process.env[k];
      else process.env[k] = env[k];
    }
    try { return fn(); } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  }

  it("colors a TTY by default", () => {
    withEnv({}, () => assert.equal(resolveColor([], tty), true));
  });

  it("does not color a pipe by default", () => {
    withEnv({}, () => assert.equal(resolveColor([], pipe), false));
  });

  it("honours --no-color above everything else", () => {
    withEnv({ FORCE_COLOR: "1" }, () => assert.equal(resolveColor(["--no-color"], tty), false));
  });

  it("lets --color force color through a pipe", () => {
    withEnv({}, () => assert.equal(resolveColor(["--color"], pipe), true));
  });

  it("treats an empty NO_COLOR as unset, per no-color.org", () => {
    withEnv({ NO_COLOR: "" }, () => assert.equal(resolveColor([], tty), true));
    withEnv({ NO_COLOR: "1" }, () => assert.equal(resolveColor([], tty), false));
  });

  it("skips color on a dumb terminal", () => {
    withEnv({ TERM: "dumb" }, () => assert.equal(resolveColor([], tty), false));
  });
});

describe("EXIT_USAGE", () => {
  it("stays at 1, the code these CLIs have always used for a failure", () => {
    // Deliberately not sysexits' 64: a published exit code is part of the
    // CLI's contract and someone's pipeline may branch on it.
    assert.equal(EXIT_USAGE, 1);
  });
});
