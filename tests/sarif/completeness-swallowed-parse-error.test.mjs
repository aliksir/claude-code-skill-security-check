// Fixture 3 of 3 (issue #24): parse error swallowed — the run analysed
// less than it was handed, said nothing about it, and exited 0.
//
// Provenance: both documents are real, unedited skil-lock output
// (skills-lock/skil-lock at 0.2.3-9-gc0ebb91), captured in warn mode —
// the default path, since warn is what you get with no .skil-lock.yaml.
//
//   swallowed-parse-error.sarif.json
//     Tree with two locked skills. After locking, one skill's SKILL.md
//     was corrupted (required `name` frontmatter field removed) so it
//     fails to parse. The scanner drops it and exits 0 with zero
//     capability findings.
//
//   swallowed-parse-error-complete.sarif.json
//     Tree with one locked skill, unchanged. A genuinely complete,
//     genuinely clean run. Also exit 0, zero findings.
//
// WHAT CHANGED SINCE THIS FIXTURE WAS FIRST FILED. As originally
// captured, these two documents were `deepEqual` — the whole artifact,
// byte for byte. The emitter has since been fixed (skil-lock#44): every
// run now declares its coverage at run level, and each unanalysed skill
// gets a warning notification naming the file and reason. The fixtures
// were regenerated against the fixed emitter, as the README said they
// would be.
//
// The fixture is kept, and is more useful than before, because it now
// discriminates the two RULES rather than merely recording a defect:
// the ratified v1 rule still returns the same verdict for both runs,
// while the deferred v1.x run-level declaration separates them. That
// contrast is the evidence for the deferred item, from an emitter that
// implemented it.
//
// These fixtures discriminate readings, not schema conformance: given
// §3.14.23 a capped run would not pass a conformance check anyway.
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

describe("completeness: swallowed parse error (skil-lock warn mode, default path)", () => {
  const swallowed = load("swallowed-parse-error.sarif.json");
  const complete = load("swallowed-parse-error-complete.sarif.json");

  it("both runs report zero capability findings and exit successfully", () => {
    // The premise of the case: nothing in the results array
    // distinguishes them, and the analysis itself completed in both.
    assert.equal(swallowed.runs[0].results.length, 0);
    assert.equal(complete.runs[0].results.length, 0);
    assert.equal(swallowed.runs[0].invocations[0].executionSuccessful, true);
    assert.equal(complete.runs[0].invocations[0].executionSuccessful, true);
  });

  it("the ratified v1 rule STILL returns the same verdict for both", () => {
    // The v1 split (appliedCap in run.properties, droppedCount in
    // toolExecutionNotifications) passes this pair vacuously: this
    // emitter caps nothing and withholds no findings, so it emits
    // neither key, and a run that discloses nothing is
    // indistinguishable from one with nothing to disclose.
    const a = readCompleteness(swallowed.runs[0]);
    const b = readCompleteness(complete.runs[0]);
    assert.deepEqual(a, b);
    assert.equal(a.verdict, "unknown");
  });

  it("the deferred v1.x run-level declaration DOES separate them", () => {
    // This is the argument for the deferred item, as an assertion
    // rather than a claim: the same two runs that v1 cannot tell apart
    // are distinguished the moment the emitter states its coverage.
    const a = readRunDeclaration(swallowed.runs[0]);
    const b = readRunDeclaration(complete.runs[0]);
    assert.notDeepEqual(a, b);
    assert.equal(a.basis, "partial");
    assert.equal(b.basis, "complete");
    assert.equal(a.covered, "incomplete");
    assert.equal(b.covered, "all-inputs-analysed");
    assert.deepEqual(a.counts, { discovered: 2, analysed: 1, unanalysed: 1 });
  });

  it("the incomplete run names the file it did not analyse", () => {
    // A count alone would let a consumer know something is missing
    // without being able to act. The notification carries the path and
    // the reason, at warning level — executionSuccessful stays true
    // because the analysis completed, it just covered less than it was
    // handed (SARIF §3.58.6).
    const notes = swallowed.runs[0].invocations[0].toolExecutionNotifications;
    assert.equal(notes.length, 1);
    assert.equal(notes[0].level, "warning");
    assert.equal(notes[0].properties.skilLockKind, "skill-not-analysed");
    assert.equal(
      notes[0].properties.path,
      ".claude/skills/release-notes/SKILL.md",
    );
    assert.match(notes[0].message.text, /was not analysed/);
    // The complete run emits no notifications at all.
    assert.equal(
      complete.runs[0].invocations[0].toolExecutionNotifications,
      undefined,
    );
  });

  it("neither run carries a path outside the repository", () => {
    // Regression: the first working version of the fix embedded the
    // absolute SKILL.md path in the notification, which in a report
    // meant to be uploaded and merged leaks a CI runner's directory
    // layout or a developer's home directory and username.
    for (const doc of [swallowed, complete]) {
      const text = JSON.stringify(doc);
      assert.ok(!/"\/(home|Users|tmp)\//.test(text), "absolute path in report");
    }
  });
});
