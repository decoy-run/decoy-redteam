import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { evaluateOutcome, buildStories } from "../lib/engine.mjs";

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
