// Discriminating fixtures for the completeness split adopted for envelope v1
// (issue #24): `run.properties.appliedCap` is configuration, declared whether
// or not the bound fired; `droppedCount` is an event, carried in
// `invocations[].toolExecutionNotifications` at `warning` once a drop occurs.
//
// SCOPE — read this before treating any case here as a validation target.
// These fixtures assert *readings*, not conformance. Per SARIF §3.14.23,
// `results` SHALL contain all results the tool detected, so a run that caps its
// result array is already non-conformant and no schema check would pass it.
// What is being discriminated is narrower: whether a consumer holding only the
// artifact can tell apart three situations the schema renders identical.
//
//   1. a bounded run that says so
//   2. a detector-level bound, which withholds no finding and must not be
//      reported as though it did
//   3. a run that analysed less than it was handed and said nothing
//
// Case 3 is the one that matters most, and the one the split-key rule passes
// vacuously: the tool knew, and the knowledge never reached the artifact.
//
// No imports from lib/ — there is no completeness module to exercise yet.
// These pin the intended reading so that when one is written, the reading it
// has to satisfy is already written down.
import { describe, it } from "node:test";
import assert from "node:assert/strict";

const CAP = 4096;

/** Minimal well-formed run; each case layers its own shape on top. */
function makeRun({ properties, notifications, results = [], successful = true } = {}) {
  const invocation = { executionSuccessful: successful };
  if (notifications) invocation.toolExecutionNotifications = notifications;
  const run = {
    tool: { driver: { name: "example-scanner", version: "1.0.0" } },
    invocations: [invocation],
    results,
  };
  if (properties) run.properties = properties;
  return run;
}

/**
 * The consumer-side rule under test, written once so every case is read by the
 * same logic a merged view would apply: given this run alone, what can a reader
 * conclude about completeness?
 */
function readCompleteness(run) {
  const declaredCap = run.properties?.appliedCap;
  const note = (run.invocations?.[0]?.toolExecutionNotifications ?? []).find(
    (n) => n.properties?.droppedCount !== undefined,
  );
  if (note) {
    return { state: "bounded-and-declared", cap: declaredCap, dropped: note.properties.droppedCount };
  }
  if (declaredCap !== undefined) {
    return { state: "bounded-nothing-withheld", cap: declaredCap, dropped: 0 };
  }
  return { state: "unknown", cap: undefined, dropped: undefined };
}

describe("case 1: bounded run that declares itself", () => {
  const run = makeRun({
    properties: { appliedCap: CAP },
    notifications: [
      {
        level: "warning",
        message: { text: `1 result snippet omitted: match exceeds the ${CAP}-character cap.` },
        properties: { droppedCount: 1 },
      },
    ],
    results: [{ ruleId: "EXAMPLE-001", level: "error", message: { text: "finding" } }],
  });

  it("keeps executionSuccessful true, because the analysis completed", () => {
    assert.equal(run.invocations[0].executionSuccessful, true);
  });

  it("reports the drop at warning and never escalates to error", () => {
    const note = run.invocations[0].toolExecutionNotifications[0];
    assert.equal(note.level, "warning");
  });

  it("carries the cap at run level and does not duplicate it in the event", () => {
    assert.equal(run.properties.appliedCap, CAP);
    assert.equal(
      run.invocations[0].toolExecutionNotifications[0].properties.appliedCap,
      undefined,
    );
  });

  it("lets a consumer resolve the count against the bound that produced it", () => {
    assert.deepEqual(readCompleteness(run), {
      state: "bounded-and-declared",
      cap: CAP,
      dropped: 1,
    });
  });
});

describe("case 1b: bound declared, nothing withheld", () => {
  // Why appliedCap is unconditional. Were it emitted only on a drop, this run
  // would be byte-identical to a tool that bounds nothing, and the silence
  // would be an ambiguity rather than a claim.
  const bounded = makeRun({ properties: { appliedCap: CAP } });
  const unbounded = makeRun();

  it("emits no notification, because nothing was dropped", () => {
    assert.equal(bounded.invocations[0].toolExecutionNotifications, undefined);
  });

  it("stays distinguishable from a tool that bounds nothing", () => {
    assert.equal(readCompleteness(bounded).state, "bounded-nothing-withheld");
    assert.equal(readCompleteness(unbounded).state, "unknown");
  });
});

describe("case 2: detector-level bound withholds no finding", () => {
  // A detector that discards oversized tokens before considering them (a path
  // matcher skipping tokens over 512 bytes, say) never forms a finding to
  // withhold. Publishing its count of rejected inputs as droppedCount would put
  // a number under a key that means something else: inputs never examined, not
  // findings held back. Different quantities, so they cannot share a carrier.
  const run = makeRun({
    results: [{ ruleId: "EXAMPLE-002", level: "warning", message: { text: "finding" } }],
  });

  it("emits no droppedCount, because no finding was withheld", () => {
    const notes = run.invocations[0].toolExecutionNotifications ?? [];
    assert.equal(notes.some((n) => n.properties?.droppedCount !== undefined), false);
  });

  it("does not borrow appliedCap, which describes the result-level cap", () => {
    // Deliberately absent rather than set to 512. appliedCap as ratified
    // declares the bound on what reaches `results`; a consumer reading it as
    // "snippets may be capped at 512" would be misled, since this run's result
    // set is whole. Whether v1 should also carry detector-level bounds, and
    // under which key, is a spec question and not one a fixture should settle.
    assert.equal(run.properties, undefined);
  });

  it("therefore reads as unknown, the same as case 3", () => {
    // Worth stating plainly: this is a second instance of the case 3 gap,
    // narrower and more benign. The run is complete and reads as unverifiable,
    // so the reading is conservative rather than wrong. It still shows the v1
    // keys describe result-level bounds only.
    assert.equal(readCompleteness(run).state, "unknown");
  });
});

describe("case 3: run analysed less than it was handed and said nothing", () => {
  // The gap the split-key rule passes vacuously. A parse failure was swallowed
  // in warn mode, one input never reached analysis, and the run exits 0 with a
  // clean report. Every field present is accurate; the artifact misleads by
  // omission, which no per-field check can catch.
  const HANDED = ["a/SKILL.md", "b/SKILL.md", "c/SKILL.md"];

  const resultsFor = (uris) =>
    uris.map((uri) => ({
      ruleId: "EXAMPLE-003",
      level: "note",
      message: { text: "analysed" },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    }));

  // b/SKILL.md failed to parse and was skipped without a notification.
  const truncated = makeRun({ results: resultsFor(["a/SKILL.md", "c/SKILL.md"]) });
  // The same scanner over the same input set, with nothing skipped.
  const complete = makeRun({ results: resultsFor(HANDED) });

  it("passes every check a consumer can make, while being incomplete", () => {
    assert.equal(truncated.invocations[0].executionSuccessful, true);
    assert.equal(truncated.invocations[0].toolExecutionNotifications, undefined);
    assert.equal(readCompleteness(truncated).state, "unknown");
  });

  it("is indistinguishable from a complete run under the split-key rule", () => {
    // The whole point: the rule adopted for v1 returns the same verdict for a
    // run that saw everything and a run that quietly saw two thirds of it.
    assert.deepEqual(readCompleteness(truncated), readCompleteness(complete));
  });

  it("only shows the shortfall to a reader holding the input list", () => {
    const analysed = truncated.results.flatMap(
      (r) => r.locations?.map((l) => l.physicalLocation.artifactLocation.uri) ?? [],
    );
    const missed = HANDED.filter((uri) => !analysed.includes(uri));
    assert.deepEqual(missed, ["b/SKILL.md"]);
    // That list is external context. Nothing inside the run points at it.
  });

  it("becomes checkable once the run states its own basis", () => {
    // Deferred to v1.x per issue #24, recorded here so the gap lives in the
    // suite and not only in the thread. A run-level basis, stated even when the
    // answer is "nothing was bounded", turns the silence above into a claim a
    // consumer can test without external knowledge.
    const withBasis = {
      ...truncated,
      properties: { analysedCount: 2, handedCount: 3 },
    };
    const shortfall = (run) =>
      run.properties?.handedCount === undefined
        ? "unknowable"
        : run.properties.handedCount - run.properties.analysedCount;

    assert.equal(shortfall(truncated), "unknowable");
    assert.equal(shortfall(withBasis), 1);
    assert.equal(
      shortfall({ ...complete, properties: { analysedCount: 3, handedCount: 3 } }),
      0,
    );
  });
});
