import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateOutcome, buildStories } from "../lib/engine.mjs";
import { ATTACKS } from "../lib/attacks.mjs";

function attackById(id) {
  const a = ATTACKS.find(x => x.id === id);
  if (!a) throw new Error(`No attack ${id}`);
  return a;
}

describe("evaluateOutcome", () => {
  const baseAttack = {
    id: "TEST-001",
    severity: "high",
    category: "input-injection",
    indicators: {
      noError: true,
      successPatterns: [/table_name/i, /users/i],
      errorPatterns: [/syntax error.*near/i],
    },
    story: { title: "Test", impact: "Test", remediation: "Test" },
  };

  it("returns 'blocked' when response has an error and no pattern match", () => {
    const response = { result: null, error: { code: -32600, message: "Invalid params" }, elapsed: 10 };
    const outcome = evaluateOutcome(baseAttack, response);
    assert.strictEqual(outcome, "blocked");
  });

  it("returns 'vulnerable' when a success pattern matches the result", () => {
    const response = { result: { rows: [{ table_name: "users" }] }, error: null, elapsed: 10 };
    const outcome = evaluateOutcome(baseAttack, response);
    assert.strictEqual(outcome, "vulnerable");
  });

  it("returns 'vulnerable' when an error pattern matches the error text", () => {
    const response = { result: null, error: "syntax error near 'OR'", elapsed: 10 };
    const outcome = evaluateOutcome(baseAttack, response);
    assert.strictEqual(outcome, "vulnerable");
  });

  it("returns 'accepted' when no error but no pattern match (noError indicator)", () => {
    const response = { result: { rows: [], rowCount: 0 }, error: null, elapsed: 10 };
    const outcome = evaluateOutcome(baseAttack, response);
    assert.strictEqual(outcome, "accepted");
  });

  it("returns 'error' when response is null", () => {
    const outcome = evaluateOutcome(baseAttack, null);
    assert.strictEqual(outcome, "error");
  });

  it("returns 'blocked' for a timeout error response", () => {
    const response = { result: null, error: { code: -1, message: "Timeout" }, elapsed: 1000 };
    const outcome = evaluateOutcome(baseAttack, response);
    // Has an error, no pattern match for error pattern → blocked
    assert.strictEqual(outcome, "blocked");
  });

  it("returns 'vulnerable' on timing threshold", () => {
    const timingAttack = {
      ...baseAttack,
      indicators: { timingThresholdMs: 500 },
    };
    const response = { result: null, error: null, elapsed: 600 };
    const outcome = evaluateOutcome(timingAttack, response);
    assert.strictEqual(outcome, "vulnerable");
  });
});

describe("buildStories confidence and severity", () => {
  it("sets high confidence and original severity for pattern-matched findings", () => {
    const results = [{
      server: "s1", tool: "t1",
      attack: {
        id: "A", severity: "critical", category: "c",
        owasp: "X", ascf: "Y",
        story: { title: "T", impact: "I", remediation: "R" },
      },
      outcome: "vulnerable",
      response: { result: "data", elapsed: 10 },
      payload: "x",
    }];
    const stories = buildStories(results);
    assert.strictEqual(stories.length, 1);
    assert.strictEqual(stories[0].confidence, "high");
    assert.strictEqual(stories[0].severity, "critical");
  });

  it("sets low confidence and severity 'low' for accepted-only findings", () => {
    const results = [{
      server: "s1", tool: "t1",
      attack: {
        id: "A", severity: "critical", category: "c",
        owasp: "X", ascf: "Y",
        story: { title: "T", impact: "I", remediation: "R" },
      },
      outcome: "accepted",
      response: { result: "ok", elapsed: 10 },
      payload: "x",
    }];
    const stories = buildStories(results);
    assert.strictEqual(stories.length, 1);
    assert.strictEqual(stories[0].confidence, "low");
    assert.strictEqual(stories[0].severity, "low");
  });

  it("uses high confidence when group has mix of vulnerable and accepted", () => {
    const attack = {
      id: "A", severity: "high", category: "c",
      owasp: "X", ascf: "Y",
      story: { title: "T", impact: "I", remediation: "R" },
    };
    const results = [
      { server: "s1", tool: "t1", attack, outcome: "accepted", response: { result: "ok", elapsed: 10 }, payload: "x" },
      { server: "s1", tool: "t1", attack, outcome: "vulnerable", response: { result: "data", elapsed: 10 }, payload: "y" },
    ];
    const stories = buildStories(results);
    assert.strictEqual(stories.length, 1);
    assert.strictEqual(stories[0].confidence, "high");
    assert.strictEqual(stories[0].severity, "high");
  });
});

// ─── False-positive regression suite ────────────────────────────────────
//
// These tests pin the FP-rate fix in place. Each case was a known-bad
// signal pre-rewrite (a real tool response or error that triggered a
// false critical/high finding). Tightened indicators + payload-echo guard
// should make all of them return blocked/accepted instead.

describe("FP regression — broad indicators removed", () => {
  it("SQL tautology (INJ-001): {rows:[{result:'ok'}]} response does NOT fire critical", () => {
    const attack = attackById("INJ-001");
    const response = { result: { rows: [{ result: "ok" }], rowCount: 1 }, error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "' OR 1=1 --");
    // Previously fired "vulnerable" via /rows?/i + /result/i. Now only the
    // noError path can fire, which buildStories caps to low/low.
    assert.strictEqual(outcome, "accepted", "Tautology with no schema exfil should be 'accepted', not 'vulnerable'");
  });

  it("Path traversal (INJ-008): 'permission denied' error does NOT fire", () => {
    const attack = attackById("INJ-008");
    // Common case: tool rejects payload but error contains the word "secret"
    const response = { result: null, error: "Access denied: secret resource not allowed", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "../../.env");
    assert.strictEqual(outcome, "blocked", "Error containing 'secret' must not fire path-traversal");
  });

  it("Path traversal (INJ-008): friendly 'no such file' error does NOT fire", () => {
    const attack = attackById("INJ-008");
    const response = { result: null, error: "File not found: ../../.env (password protection enabled)", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "../../.env");
    assert.strictEqual(outcome, "blocked");
  });

  it("Path traversal (INJ-008): actual /etc/passwd content DOES fire", () => {
    const attack = attackById("INJ-008");
    const response = { result: "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "../../../etc/passwd");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("Path traversal (INJ-008): actual .env content DOES fire", () => {
    const attack = attackById("INJ-008");
    const response = { result: "DATABASE_URL=postgres://admin:s3cret@host/db\nAPI_TOKEN=tok_abc123", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "../../.env");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("SSRF localhost (INJ-011): generic '200 OK / html' response does NOT fire", () => {
    const attack = attackById("INJ-011");
    const response = { result: "<html><body>200 OK</body></html>", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "http://127.0.0.1:80");
    // Pre-fix matched /html/ + /json/ + /200/. Post-fix only INTERNAL_SERVICE_PAGE
    // anchors fire, and a generic body doesn't qualify.
    assert.strictEqual(outcome, "accepted");
  });

  it("SSRF localhost (INJ-011): internal admin panel body DOES fire", () => {
    const attack = attackById("INJ-011");
    const response = { result: "<html><body>Internal admin panel</body></html>", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "http://127.0.0.1:8080");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("Command injection (INJ-005): tool echoes 'whoami' in error does NOT fire", () => {
    const attack = attackById("INJ-005");
    // Pre-fix: /whoami/i + /root/i would match the echoed payload itself.
    const response = { result: null, error: "Unknown command: echo test; whoami (rejected by allowlist)", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "echo test; whoami");
    assert.strictEqual(outcome, "blocked");
  });

  it("Command injection (INJ-005): actual id output DOES fire", () => {
    const attack = attackById("INJ-005");
    const response = { result: "test\nuid=0(root) gid=0(root) groups=0(root)", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "echo test; id");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("Credential exposure (CRD-002): tool error mentioning 'password' does NOT fire critical", () => {
    const attack = attackById("CRD-002");
    const response = { result: null, error: "Could not open .env: password-protected vault is locked", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, ".env");
    assert.strictEqual(outcome, "blocked");
  });

  it("Credential exposure (CRD-002): actual env content DOES fire", () => {
    const attack = attackById("CRD-002");
    const response = { result: "STRIPE_SECRET_KEY=sk_live_aaaaaaaaaaaaaaaaaaaa\nDATABASE_URL=postgres://u:p@h/d", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, ".env");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("Error oracle (CRD-003): a 'version mismatch' error does NOT fire", () => {
    const attack = attackById("CRD-003");
    // Pre-fix: bare /version/i matched. Post-fix needs structural stack
    // trace shape.
    const response = { result: null, error: "Schema version mismatch (expected 3, got 2)", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, { path: "/nope" });
    assert.strictEqual(outcome, "blocked");
  });

  it("Error oracle (CRD-003): a real stack trace DOES fire", () => {
    const attack = attackById("CRD-003");
    const response = { result: null, error: "TypeError: bad arg\n    at handle (/app/node_modules/foo/index.js:42:13)\n    at next (internal/process/task_queues.js:95:5)", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, { path: "/nope" });
    assert.strictEqual(outcome, "vulnerable");
  });
});

describe("FP regression — template injection (SSTI)", () => {
  // INJ-013's old oracle was a bare `49` (from 7×7), which false-fired on any
  // tool that returned the number 49. The rebuilt oracle is the distinctive
  // product 1337×31337=41897569, and INJ-017 anchors on engine-emitted object
  // reprs. Both can only come from server-side evaluation, never a payload echo.

  it("Template injection (INJ-013): '49 results found' does NOT fire", () => {
    const attack = attackById("INJ-013");
    const response = { result: "49 results found", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{1337*31337}}");
    assert.strictEqual(outcome, "blocked", "A benign 49 must no longer fire template injection");
  });

  it("Template injection (INJ-013): payload echoed verbatim (not evaluated) does NOT fire", () => {
    const attack = attackById("INJ-013");
    const response = { result: "Rendered template: {{1337*31337}}", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{1337*31337}}");
    assert.strictEqual(outcome, "blocked", "Echoing the unevaluated expression is not evaluation");
  });

  it("Template injection (INJ-013): a near-miss number (off by one) does NOT fire", () => {
    const attack = attackById("INJ-013");
    const response = { result: "Order total: 41897568", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{1337*31337}}");
    assert.strictEqual(outcome, "blocked");
  });

  it("Template injection (INJ-013): the evaluated product DOES fire", () => {
    const attack = attackById("INJ-013");
    const response = { result: "Hello, your code is 41897569", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{1337*31337}}");
    assert.strictEqual(outcome, "vulnerable", "The evaluated product is unambiguous SSTI");
  });

  it("Template injection (INJ-013): baseline already emitting the product is suppressed", () => {
    const attack = attackById("INJ-013");
    const baseline = { resultText: "build #41897569", errorText: "", elapsed: 5 };
    const response = { result: "build #41897569", error: null, elapsed: 6 };
    const outcome = evaluateOutcome(attack, response, "{{1337*31337}}", baseline);
    assert.strictEqual(outcome, "blocked", "A tool that normally emits the number is not SSTI");
  });

  it("Template reflection (INJ-017): a benign string mentioning class does NOT fire", () => {
    const attack = attackById("INJ-017");
    const response = { result: "Your class enrollment is confirmed", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{ ''.__class__.__mro__ }}");
    assert.strictEqual(outcome, "blocked");
  });

  it("Template reflection (INJ-017): the engine rejecting __class__ does NOT fire", () => {
    const attack = attackById("INJ-017");
    const response = { result: null, error: "Unknown attribute '__class__' on str", elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{ ''.__class__.__mro__ }}");
    assert.strictEqual(outcome, "blocked", "A rejected probe is not evaluation");
  });

  it("Template reflection (INJ-017): Python class repr DOES fire", () => {
    const attack = attackById("INJ-017");
    const response = { result: "(<class 'str'>, <class 'object'>)", error: null, elapsed: 5 };
    const outcome = evaluateOutcome(attack, response, "{{ ''.__class__.__mro__ }}");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("Template reflection (INJ-017): Java SpEL class handle DOES fire (and survives echo guard)", () => {
    const attack = attackById("INJ-017");
    const response = { result: "class java.lang.Runtime", error: null, elapsed: 5 };
    // The payload carries `java.lang.Runtime` but not the engine-emitted
    // `class ` prefix, so the full match isn't a payload substring.
    const outcome = evaluateOutcome(attack, response, "${T(java.lang.Runtime)}");
    assert.strictEqual(outcome, "vulnerable");
  });
});

describe("FP regression — baseline suppression", () => {
  // Baseline is a benign call against the tool captured before attacks. If
  // the same indicator already matches the baseline, the attack response
  // wasn't attack-specific behavior — it's just what the tool normally
  // returns. Suppress.

  it("indicator match present in baseline.resultText is suppressed", () => {
    const attack = { indicators: { successPatterns: [/-----BEGIN PRIVATE KEY-----/] } };
    const baseline = {
      resultText: "Example response: -----BEGIN PRIVATE KEY-----\\nMIIEvQ... (sample)",
      errorText: "",
      elapsed: 5,
    };
    const response = { result: "-----BEGIN PRIVATE KEY-----\nMIIEvQ...", error: null, elapsed: 10 };
    const outcome = evaluateOutcome(attack, response, "../../.ssh/id_rsa", baseline);
    assert.strictEqual(outcome, "blocked", "anchor already in baseline must not fire");
  });

  it("indicator match NOT in baseline still fires when present in attack response", () => {
    const attack = { indicators: { successPatterns: [/-----BEGIN PRIVATE KEY-----/] } };
    const baseline = { resultText: "normal response, no key", errorText: "", elapsed: 5 };
    const response = { result: "-----BEGIN PRIVATE KEY-----\nMIIEvQ...", error: null, elapsed: 10 };
    const outcome = evaluateOutcome(attack, response, "../../.ssh/id_rsa", baseline);
    assert.strictEqual(outcome, "vulnerable");
  });

  it("timing threshold adapts to baseline elapsed (cold-start FP suppression)", () => {
    const attack = { indicators: { timingThresholdMs: 4000 } };
    // Cold start: baseline call took 3500ms. Threshold becomes max(4000, 3500*3+1000) = 11500ms.
    const baseline = { resultText: "", errorText: "", elapsed: 3500 };
    const response = { result: null, error: null, elapsed: 5000 };
    const outcome = evaluateOutcome(attack, response, "'; SELECT pg_sleep(5); --", baseline);
    assert.strictEqual(outcome, "blocked", "5s call on a 3.5s-baseline tool is not a timing oracle");
  });

  it("timing threshold still fires when attack is dramatically slower than baseline", () => {
    const attack = { indicators: { timingThresholdMs: 4000 } };
    const baseline = { resultText: "", errorText: "", elapsed: 50 }; // 50ms baseline
    const response = { result: null, error: null, elapsed: 8000 };
    const outcome = evaluateOutcome(attack, response, "'; SELECT pg_sleep(5); --", baseline);
    assert.strictEqual(outcome, "vulnerable", "8s vs 50ms baseline is a real timing signal");
  });

  it("no baseline → falls back to fixed timing threshold (backward compat)", () => {
    const attack = { indicators: { timingThresholdMs: 4000 } };
    const response = { result: null, error: null, elapsed: 5000 };
    const outcome = evaluateOutcome(attack, response, "'; SELECT pg_sleep(5); --");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("errored baseline is ignored — adaptive timing falls back to the fixed threshold", () => {
    // captureBaselines marks errored:true when the calibration call times
    // out. Its elapsed value is the timeout floor, not a real latency.
    // Using it for adaptive timing would mask a real blind-injection
    // signal on the very tools that are slow enough to time out the
    // baseline. Treat as absent.
    const attack = { indicators: { timingThresholdMs: 4000 } };
    const erroredBaseline = { errored: true, elapsed: 3000, resultText: "", errorText: "baseline timeout" };
    const response = { result: null, error: null, elapsed: 5000 };
    const outcome = evaluateOutcome(attack, response, "'; SELECT pg_sleep(5); --", erroredBaseline);
    assert.strictEqual(outcome, "vulnerable", "Errored baseline should not raise the timing floor");
  });

  it("errored baseline is ignored — indicator suppression doesn't fire on synthetic errorText", () => {
    // Defensive: a future indicator pattern that happens to match the
    // string "baseline timeout" mustn't get suppressed by the synthetic
    // baseline content.
    const attack = { indicators: { errorPatterns: [/baseline/i] } };
    const erroredBaseline = { errored: true, elapsed: 3000, resultText: "", errorText: "baseline timeout" };
    const response = { result: null, error: "baseline failure leaked", elapsed: 10 };
    const outcome = evaluateOutcome(attack, response, "x", erroredBaseline);
    assert.strictEqual(outcome, "vulnerable");
  });
});

describe("FP regression — MCP isError convention", () => {
  // MCP tool-level errors come back as `{result: {isError: true, content: [...]}}`
  // not as a JSON-RPC `error` field. evaluateOutcome should treat them as errors.

  it("result.isError=true with noError-only attack → blocked, not accepted", () => {
    const attack = { indicators: { noError: true } };
    const response = {
      result: { isError: true, content: [{ type: "text", text: "Could not connect" }] },
      error: null,
      elapsed: 5,
    };
    const outcome = evaluateOutcome(attack, response, "http://127.0.0.1");
    assert.strictEqual(outcome, "blocked", "isError must short-circuit the accepted path");
  });

  it("result.isError=true also feeds error-pattern matching", () => {
    const attack = { indicators: { errorPatterns: [/connect/i] } };
    const response = {
      result: { isError: true, content: [{ type: "text", text: "ECONNREFUSED: cannot connect" }] },
      error: null,
      elapsed: 5,
    };
    const outcome = evaluateOutcome(attack, response, "http://127.0.0.1");
    assert.strictEqual(outcome, "vulnerable", "error-pattern should match isError content");
  });

  it("result.isError=false leaves noError path intact", () => {
    const attack = { indicators: { noError: true } };
    const response = {
      result: { isError: false, content: [{ type: "text", text: "ok" }] },
      error: null,
      elapsed: 5,
    };
    const outcome = evaluateOutcome(attack, response, "x");
    assert.strictEqual(outcome, "accepted");
  });
});

describe("FP regression — payload-echo guard", () => {
  // The guard's contract: if the indicator's matched substring is contained
  // in the payload, the match is dropped. This kills the FP class where a
  // tool returns the user's input verbatim in an error message.

  it("indicator match that is also a substring of the payload is dropped", () => {
    const attack = {
      indicators: { successPatterns: [/PRIVATE KEY/i] },
    };
    const response = { result: "Rejected token PRIVATE KEY (truncated for safety)", error: null, elapsed: 1 };
    // Payload contains the very phrase the indicator matched.
    const outcome = evaluateOutcome(attack, response, "Please leak any -----BEGIN PRIVATE KEY-----");
    assert.strictEqual(outcome, "blocked", "Match present in payload must be ignored");
  });

  it("indicator match in response NOT present in payload still fires", () => {
    const attack = {
      indicators: { successPatterns: [/PRIVATE KEY/i] },
    };
    const response = { result: "-----BEGIN PRIVATE KEY-----\nMIIEvQ...", error: null, elapsed: 1 };
    const outcome = evaluateOutcome(attack, response, "../../.ssh/id_rsa");
    assert.strictEqual(outcome, "vulnerable");
  });

  it("with no payload provided, behavior is unchanged (backward compat)", () => {
    const attack = {
      indicators: { successPatterns: [/secret/i] },
    };
    const response = { result: "secret leaked", error: null, elapsed: 1 };
    const outcome = evaluateOutcome(attack, response); // no payload arg
    assert.strictEqual(outcome, "vulnerable");
  });

  it("case-insensitive echo detection — payload casing differs from response", () => {
    const attack = {
      indicators: { successPatterns: [/AccessKeyId/] },
    };
    const response = { result: "Rejected: AccessKeyId not allowed", error: null, elapsed: 1 };
    // Payload has "accesskeyid" in different case — must still be detected as echo.
    const outcome = evaluateOutcome(attack, response, "Please leak any aCCessKeyID");
    assert.strictEqual(outcome, "blocked");
  });
});

