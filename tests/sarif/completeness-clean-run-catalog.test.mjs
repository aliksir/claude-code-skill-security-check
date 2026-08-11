// Fixture 4 (issue #24): the clean run, and the rule-catalog convention
// that decides whether a validator accepts it.
//
// @aliksir found this defect in his own code and reported it in #24:
// `validateRules` rejects an empty rules array, and a clean run has an
// empty rules array, so the validator declares a clean scan invalid. He
// also stated the limit himself — `validateRules` has no caller outside
// its own test file, so it has never rejected a real run.
//
// This fixture exists to make that executable, and to say the one thing
// the report of the defect did not: **whether a clean run has an empty
// rules array is not a property of the run. It is a property of the
// emitter's catalog convention.** Two emitters can produce a clean scan
// of the same repo and hand the validator opposite inputs.
//
// WHAT IS ASSERTED ON HERE IS NOT WHAT EXECUTES.
// `lib/sarif/draft-validator.mjs` is imported by exactly one file in
// this repo, `tests/sarif/draft-validator.test.mjs`. Nothing on the scan
// path calls it. The same is true of `enrichWithArtifactDigest` in
// `lib/sarif/artifact-digest.mjs`. So every assertion below describes a
// module that is specified and tested and not wired in, and a reader who
// takes these as statements about what a `claude-code-skill-security-check`
// run does will be wrong.
//
// That note is a test, not a comment — see "the wiring note" at the
// bottom. A prose disclaimer about wiring is exactly the kind of claim
// this thread keeps finding to have gone stale silently, so the note
// fails the build if it stops being true in either direction.
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync, readdirSync } from "fs";
import { validateRules } from "../../lib/sarif/draft-validator.mjs";
import { readRunDeclaration } from "./fixtures/completeness/read-run-declaration.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "fixtures", "completeness");

const load = (name) =>
  JSON.parse(readFileSync(join(fixtures, name), "utf8"));

// The one captured document. Real, unedited skil-lock output — see the
// README for the reproduction. Everything else in this file is
// constructed, and each construction says why it could not be captured.
const cleanRun = load("clean-run-skil-lock.sarif.json");

describe("a clean run, as one real emitter actually emits it", () => {
  it("carries the full rule catalog and zero results", () => {
    const run = cleanRun.runs[0];
    assert.equal(run.results.length, 0);
    assert.equal(run.tool.driver.rules.length, 6);
  });

  it("declares its coverage rather than leaving it to be inferred", () => {
    // The distinction this whole sub-thread turns on: "no findings" and
    // "nothing was looked at" are different documents, and only one of
    // them is entitled to be read as an all-clear.
    const d = readRunDeclaration(cleanRun.runs[0]);
    assert.equal(d.declared, true);
    assert.equal(d.basis, "complete");
    assert.equal(d.covered, "all-inputs-analysed");
    assert.equal(d.counts.unanalysed, 0);
  });

  it("is rejected by validateRules for ID format, not for the empty set", () => {
    // Worth having explicitly so nobody reads the next describe() block
    // as "skil-lock output breaks aliksir's validator." It does, and for
    // an unrelated and legitimate reason: these are native rule IDs, not
    // envelope IDs. The empty-set defect is not reachable from here.
    const result = validateRules(cleanRun.runs[0].tool.driver.rules);
    assert.equal(result.valid, false);
    assert.ok(
      result.errors.every((e) => e.includes("ID フォーマット")),
      `expected only ID-format errors, got: ${JSON.stringify(result.errors)}`,
    );
  });
});

// Both catalogs below use ATR IDs, because that is the only way to reach
// the empty-set question: a document with native IDs is rejected on
// format first (asserted above). No emitter in the thread currently
// publishes an ATR-ID catalog, so these are constructed and are not
// presented as anyone's output.
const FULL_CATALOG = [
  { id: "ATR-SHELL-001" },
  { id: "ATR-NET-002" },
];
const FIRED_ONLY_CATALOG = [];

describe("the same clean scan, two catalog conventions", () => {
  it("validates under the full-catalog convention", () => {
    assert.equal(validateRules(FULL_CATALOG).valid, true);
  });

  it("does not validate under the fired-only convention", () => {
    const result = validateRules(FIRED_ONLY_CATALOG);
    assert.equal(result.valid, false);
    assert.deepEqual(result.errors, ["ルール配列が空または未定義"]);
  });

  it("splits on the convention alone — the scan is identical", () => {
    // Neither array describes a different scan. Both describe a run in
    // which nothing fired. The verdicts differ because one emitter
    // publishes every rule it could report and the other publishes only
    // the rules it did report, and the validator has no way to ask which
    // it is holding.
    //
    // This is the part that is not fixed by special-casing []. A
    // validator that accepts the empty array still cannot tell a
    // fired-only clean run from a full-catalog run whose catalog failed
    // to serialise. Distinguishing them needs the run to say so — which
    // is the run-level declaration the second assertion in this file
    // reads, and which the fired-only document would also have to carry.
    assert.notEqual(
      validateRules(FULL_CATALOG).valid,
      validateRules(FIRED_ONLY_CATALOG).valid,
    );
  });

  it("is not repaired by the run-level declaration alone", () => {
    // Guard against over-claiming for the declaration. A fired-only
    // clean run that DOES declare complete coverage is still rejected,
    // because validateRules never looks at run.properties. The
    // declaration fixes what a consumer can read; it does not reach a
    // validator that inspects only the catalog.
    const declaringRun = {
      properties: {
        completeness: {
          basis: "complete",
          resultsBounded: false,
          skillsDiscovered: 1,
          skillsAnalysed: 1,
          skillsUnanalysed: 0,
        },
      },
      tool: { driver: { rules: FIRED_ONLY_CATALOG } },
    };
    assert.equal(readRunDeclaration(declaringRun).covered, "all-inputs-analysed");
    assert.equal(validateRules(declaringRun.tool.driver.rules).valid, false);
  });
});

// The wiring note.
//
// The disclosure at the top of this file — that the asserted-on modules
// have no caller on the scan path — is true when written and is the kind
// of statement that rots without anyone noticing. So it is checked.
//
// If someone wires validateRules or enrichWithArtifactDigest into the
// run, this fails, and the fix is to update the note at the top of this
// file rather than to delete this test.
describe("the wiring note", () => {
  const modules = {
    validateRules: "lib/sarif/draft-validator.mjs",
    enrichWithArtifactDigest: "lib/sarif/artifact-digest.mjs",
  };

  const repoRoot = join(here, "..", "..");
  const sourceFiles = (dir) =>
    readdirSync(join(repoRoot, dir), { withFileTypes: true })
      .filter((e) => e.isFile() && (e.name.endsWith(".mjs") || e.name.endsWith(".js")))
      .map((e) => join(dir, e.name));

  for (const [symbol, modulePath] of Object.entries(modules)) {
    it(`${symbol} is still imported only from its own test file`, () => {
      const candidates = [
        ...sourceFiles("lib/sarif"),
        ...sourceFiles("lib"),
        ...sourceFiles("tests/sarif"),
      ];
      const importers = candidates.filter((f) => {
        if (f === modulePath) return false;
        return readFileSync(join(repoRoot, f), "utf8").includes(`import { ${symbol}`)
          || new RegExp(`\\b${symbol}\\s*\\(`).test(readFileSync(join(repoRoot, f), "utf8"));
      });
      // This file is one of them, by construction.
      const others = importers.filter((f) => !f.endsWith("completeness-clean-run-catalog.test.mjs"));

      assert.deepEqual(
        others,
        [join("tests/sarif", `${modulePath.split("/").pop().replace(".mjs", "")}.test.mjs`)],
        `${symbol} has acquired or lost callers; the disclosure at the top of this file must be updated to match. Found: ${JSON.stringify(others)}`,
      );
    });
  }
});
