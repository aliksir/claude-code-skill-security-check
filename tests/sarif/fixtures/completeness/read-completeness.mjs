// Reference consumer for the completeness rule ratified in issue #24.
//
// The v1 rule, as accepted:
//   - `run.properties.appliedCap` — SHOULD, run-level. Declared whether or
//     not the bound fired: configuration, not an event.
//   - `invocations[].toolExecutionNotifications[]` at `level: "warning"`
//     carrying `droppedCount` — MUST once a drop occurs: an event,
//     specific to this run.
//
// This is deliberately the whole rule and nothing else. The fixtures in
// this directory exist to show what verdicts this reader can and cannot
// reach on real emitter output — they discriminate READINGS, not schema
// conformance. Per SARIF §3.14.23 a run with a capped `results` array is
// non-conformant regardless of any disclosure, so do not mistake these
// fixtures for a validation target.
export function readCompleteness(run) {
  const declaredCap = run.properties?.appliedCap ?? null;
  const drops = [];
  for (const inv of run.invocations ?? []) {
    for (const n of inv.toolExecutionNotifications ?? []) {
      if (n.properties?.droppedCount !== undefined) {
        drops.push({ level: n.level, droppedCount: n.properties.droppedCount });
      }
    }
  }
  if (drops.length > 0) return { declaredCap, drops, verdict: "bounded-disclosed" };
  if (declaredCap !== null) return { declaredCap, drops, verdict: "complete-under-declared-bound" };
  // No declaration anywhere. Under v1 SHOULD this is conformant — and it is
  // exactly the silence the deferred v1.x run-level declaration would turn
  // into a claim.
  return { declaredCap, drops, verdict: "unknown" };
}
