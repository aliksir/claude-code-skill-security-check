// Reference consumer for the run-level completeness declaration
// DEFERRED to v1.x in issue #24 — the rule that makes an emitter state
// its coverage basis even when the answer is "nothing was bounded", so
// that silence becomes a claim rather than an absence.
//
// This is deliberately a SECOND reader, kept separate from
// read-completeness.mjs (which implements only the ratified v1 rule).
// Running both over the same fixtures is what shows which failures each
// rule actually catches — the fixtures discriminate the two readings.
//
// The shape read here is skil-lock's implementation of the proposal
// (`run.properties.completeness`). It is not ratified and the key names
// are one emitter's choice; what the fixtures demonstrate is the
// behaviour of the rule, not the spelling.
export function readRunDeclaration(run) {
  const c = run.properties?.completeness;
  if (!c) {
    // No declaration at all. Indistinguishable from an emitter that has
    // nothing to declare — which is the ambiguity the rule closes.
    return { declared: false, basis: "undeclared", covered: null };
  }
  return {
    declared: true,
    basis: c.basis,
    resultsBounded: c.resultsBounded,
    covered:
      c.skillsUnanalysed === 0 && c.basis === "complete"
        ? "all-inputs-analysed"
        : "incomplete",
    counts: {
      discovered: c.skillsDiscovered,
      analysed: c.skillsAnalysed,
      unanalysed: c.skillsUnanalysed,
    },
  };
}
