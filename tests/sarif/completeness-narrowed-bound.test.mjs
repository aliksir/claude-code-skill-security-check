// Fixture 2 of 3 (issue #24): a bound on detector INPUT — not a result
// cap, not a narrowed reproduced region. The category recorded in the
// thread as "bounds that are not result caps".
//
// Provenance: both documents are real, unedited skil-lock output
// (skills-lock/skil-lock at 0.2.3-9-gc0ebb91), warn mode. The bound is
// `looksLikePath` in internal/detector/paths/paths.go, which discards
// any token longer than 512 bytes before it is ever considered as a
// path. The tool does not hold a finding back; it never forms one.
//
// The two runs differ by one thing only — the length of the path in an
// otherwise identical edit to a locked skill's SKILL.md:
//
//   narrowed-bound-control.sarif.json
//     Edit adds `echo ok > /tmp/deploy.log` (15-byte path). The run
//     reports SKL-FILE-WRITE, file_writes added — the detector saw it.
//
//   narrowed-bound.sarif.json
//     Same edit with a 525-byte path. The write is discarded before
//     detection, and the finding DEGRADES rather than disappears: the
//     run falls back to a generic SKL-OTHER content_hash-modified
//     result. The capability surface reads unchanged.
//
// THE POINT OF KEEPING THIS FIXTURE AFTER THE EMITTER WAS FIXED.
// skil-lock#44 added a run-level completeness declaration, which closes
// the sibling case (a skill that never parsed). It does NOT close this
// one, and the fixture now proves that: both runs below declare
// `basis: "complete"` with `skillsUnanalysed: 0`, and both are telling
// the truth — the skill parsed and was analysed. The bound sits inside
// the detector, one layer below anything a coverage count can see.
//
// So the three failure classes are genuinely distinct, and a rule aimed
// at one does not reach the others:
//   - capped results array   -> v1 appliedCap / droppedCount
//   - unanalysed input       -> deferred v1.x run-level declaration
//   - bounded detector input -> neither; still open
//
// These fixtures discriminate readings, not schema conformance.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import { readCompleteness } from "./fixtures/completeness/read-completeness.mjs";
import { readRunDeclaration } from "./fixtures/completeness/read-run-declaration.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixDir = join(__dirname, "fixtures/completeness");
const load = (name) => JSON.parse(readFileSync(join(fixDir, name), "utf-8"));

describe("completeness: detector-input bound (skil-lock looksLikePath, 512 bytes)", () => {
  const control = load("narrowed-bound-control.sarif.json");
  const bounded = load("narrowed-bound.sarif.json");

  it("control: the short-path write is detected and attributed", () => {
    const results = control.runs[0].results;
    assert.equal(results.length, 1);
    assert.equal(results[0].ruleId, "SKL-FILE-WRITE");
    assert.equal(results[0].properties.capability, "file_writes");
    assert.equal(results[0].properties.change, "added");
  });

  it("bounded: the long-path write degrades to an unattributed content-hash delta", () => {
    const results = bounded.runs[0].results;
    assert.equal(results.length, 1);
    assert.equal(results[0].ruleId, "SKL-OTHER");
    assert.equal(results[0].properties.capability, "content_hash");
    // The results array is NOT capped — one entry in, one entry out.
    // What was lost is attribution: a write to a path became "content
    // changed, no capability delta detected".
  });

  it("deliberately does NOT declare appliedCap for this bound", () => {
    // As ratified, `appliedCap` describes the result-level cap. The
    // results array here is whole — borrowing the key for a
    // detector-level bound would tell a consumer the result set may be
    // capped when it is not. Likewise `droppedCount` cannot carry it
    // honestly: it would count rejected inputs, not withheld findings,
    // publishing a number that does not mean what the key says.
    const comp = bounded.runs[0].properties.completeness;
    assert.equal(comp.appliedCap, undefined);
    assert.equal(comp.droppedCount, undefined);
    assert.equal(comp.resultsBounded, false);
  });

  it("the ratified v1 rule cannot distinguish the bounded run from the control", () => {
    const a = readCompleteness(bounded.runs[0]);
    const b = readCompleteness(control.runs[0]);
    assert.deepEqual(a, b);
    assert.equal(a.verdict, "unknown");
  });

  it("the deferred v1.x run-level declaration cannot either — and is not wrong to say so", () => {
    // Both runs declare complete coverage, and both declarations are
    // accurate: every discovered skill was analysed. The bound is not a
    // coverage gap over inputs, it is a gap inside the analysis of an
    // input that was fully read. A membership count cannot see it, so
    // the deferred rule buys nothing here.
    //
    // This is the honest limit of the fixture set, and the reason the
    // third category is worth naming separately rather than folding
    // into either existing rule.
    const a = readRunDeclaration(bounded.runs[0]);
    const b = readRunDeclaration(control.runs[0]);
    assert.deepEqual(a, b);
    assert.equal(a.basis, "complete");
    assert.equal(a.covered, "all-inputs-analysed");
    assert.deepEqual(a.counts, { discovered: 1, analysed: 1, unanalysed: 0 });
  });
});
