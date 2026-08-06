// Fixture 2 of 3 (issue #24): a bound on detector INPUT — not a result
// cap, not a narrowed reproduced region. The category recorded in the
// thread as "bounds that are not result caps".
//
// Provenance: both documents are real, unedited skil-lock output
// (skills-lock/skil-lock at 0.2.3+g5b443d9), warn mode. The bound is
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
//     result at level "note". The capability surface reads unchanged.
//
// Reproduction steps are in fixtures/completeness/README.md. These
// fixtures discriminate readings of the ratified v1 rule, not schema
// conformance (see read-completeness.mjs).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import { readCompleteness } from "./fixtures/completeness/read-completeness.mjs";

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
    // Whether this category needs a slot at all is the v1.x
    // completeness discussion, not v1.
    assert.equal(bounded.runs[0].properties, undefined);
    assert.equal(bounded.runs[0].invocations, undefined);
  });

  it("the ratified v1 rule cannot distinguish the bounded run from the control", () => {
    // Both runs read as "unknown": no declared cap, no drop event.
    // A consumer cannot separate "content change with no capability
    // effect" from "content change whose capability effect was
    // discarded before detection". This is the benign sibling of the
    // swallowed-parse-error case — same gap, lower stakes, because at
    // least a note-level delta survives here.
    const a = readCompleteness(bounded.runs[0]);
    const b = readCompleteness(control.runs[0]);
    assert.deepEqual(a, b);
    assert.equal(a.verdict, "unknown");
  });
});
