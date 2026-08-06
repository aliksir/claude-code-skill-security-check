// Fixture 3 of 3 (issue #24): parse error swallowed — the run analysed
// less than it was handed, said nothing about it, and exited 0.
//
// Provenance: both documents are real, unedited skil-lock output
// (skills-lock/skil-lock at 0.2.3+g5b443d9), captured in warn mode —
// the default path, since warn is what you get with no .skil-lock.yaml.
//
//   swallowed-parse-error.sarif.json
//     Tree with two locked skills. After locking, one skill's SKILL.md
//     was corrupted (required `name` frontmatter field removed) so it
//     fails to parse. The scanner dropped it, wrote one line to stderr
//       warning: .claude/skills/release-notes/SKILL.md: ... missing a
//       required field: "name"
//     and exited 0 with zero findings. The SARIF renderer is never
//     handed the scan errors.
//
//   swallowed-parse-error-complete.sarif.json
//     Tree with one locked skill, unchanged. A genuinely complete,
//     genuinely clean run. Also exit 0, zero findings.
//
// The defect these two files pin down: the documents are IDENTICAL.
// Not similar — deepEqual, the whole artifact. The tool knew (stderr),
// and the knowledge didn't reach the artifact. This is the set-valued
// case where a per-artifact digest cannot help: the skill that failed
// to parse has no digest, no result, and no absence anywhere in the
// report. Reproduction steps are in fixtures/completeness/README.md.
//
// These fixtures discriminate readings of the ratified v1 rule, not
// schema conformance (see read-completeness.mjs).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync } from "fs";
import { readCompleteness } from "./fixtures/completeness/read-completeness.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixDir = join(__dirname, "fixtures/completeness");
const load = (name) => JSON.parse(readFileSync(join(fixDir, name), "utf-8"));

describe("completeness: swallowed parse error (skil-lock warn mode, default path)", () => {
  const swallowed = load("swallowed-parse-error.sarif.json");
  const complete = load("swallowed-parse-error-complete.sarif.json");

  it("the incomplete run reports zero findings and carries no failure channel", () => {
    const run = swallowed.runs[0];
    assert.equal(run.results.length, 0);
    // skil-lock currently emits no invocations block at all: no
    // executionSuccessful, no toolExecutionNotifications — so it has no
    // §4 failure channel either. Documented current behaviour, not the
    // desired end state.
    assert.equal(run.invocations, undefined);
    assert.equal(run.properties, undefined);
  });

  it("the incomplete run is deepEqual to a genuinely complete run — the whole document", () => {
    // This is the strongest form of the defect: not that a consumer
    // fails to distinguish the two runs, but that there is nothing in
    // the artifact to distinguish. One of these runs was handed a skill
    // it never analysed; byte for byte, the reports are the same.
    assert.deepEqual(swallowed, complete);
  });

  it("the ratified v1 rule returns the same verdict for both runs", () => {
    // Asserted rather than commented: the adopted split (appliedCap in
    // run.properties, droppedCount in toolExecutionNotifications)
    // passes this run vacuously. A run disclosing nothing emits neither
    // key. This is the recorded v1.x gap — a mandatory run-level
    // completeness declaration is what would separate these two.
    const a = readCompleteness(swallowed.runs[0]);
    const b = readCompleteness(complete.runs[0]);
    assert.deepEqual(a, b);
    assert.equal(a.verdict, "unknown");
  });

  it("a consumer following the OWASP boundary rule finds nothing to act on", () => {
    // OWASP/www-project-agentic-skills-top-10#49: a scanner that did
    // not (fully) run must not read as clean evidence. The rule is
    // consumer-side; this run defeats it from the emitter side. Every
    // field that rule could inspect is indistinguishable from the
    // clean run's.
    const run = swallowed.runs[0];
    assert.equal(run.tool.driver.name, "skil-lock");
    assert.deepEqual(run.artifacts ?? [], []);
    assert.deepEqual(run.results, []);
  });
});
