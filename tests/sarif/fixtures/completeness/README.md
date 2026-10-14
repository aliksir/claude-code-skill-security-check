# Completeness fixtures (issue #24)

Three cases. Cases 2 and 3 are described first; case 4 (the clean run and
the rule-catalog convention) is at the bottom, and carries a disclosure
about what it asserts on.

Two of the three discriminating cases accepted in
[#24](https://github.com/aliksir/claude-code-skill-security-check/issues/24):
a **detector-input bound** (case 2) and a **swallowed parse error**
(case 3). Case 1 (bounded run with disclosure) belongs to
prompt-defense-audit / Rul1an's emitter and is not here.

The four `.sarif.json` files for cases 2 and 3 are real, unedited output
of [skills-lock/skil-lock](https://github.com/skills-lock/skil-lock) at
`0.2.3-9-gc0ebb91`, run in warn mode — the default path, since warn is
what you get with no `.skil-lock.yaml`. (Case 4 adds a fifth capture at a
later version; see its own section for why it is not re-captured at the
same one.)

**Regenerated after the emitter fix, as promised.** The first version of
these fixtures pinned pre-fix behaviour, where the swallowed-parse-error
run was `deepEqual` to a clean run. That hole is now closed
([skil-lock#44](https://github.com/skills-lock/skil-lock/pull/44)): every
run declares its coverage at run level, each unanalysed skill gets a
`warning` notification naming file and reason, and a scan that cannot run
at all emits `executionSuccessful: false` with an `error`-level
notification.

The fixtures are more useful after the fix than before, because they now
discriminate the two **rules** rather than recording one tool's defect:

| Case | Ratified v1 rule | Deferred v1.x run-level declaration |
|---|---|---|
| 3 — unanalysed input | same verdict for both runs (vacuous) | **separates them** (`partial` vs `complete`) |
| 2 — detector-input bound | same verdict for both runs | same verdict for both runs — and correctly so |

Case 2 is the honest limit: both runs declare `basis: "complete"` with
`skillsUnanalysed: 0`, and both declarations are **true** — the skill
parsed and was analysed. The bound sits inside the detector, one layer
below anything a coverage count can see. That is why the three failure
classes are worth naming separately:

- capped results array → v1 `appliedCap` / `droppedCount`
- unanalysed input → deferred v1.x run-level declaration
- bounded detector input → neither rule reaches it; still open

Two readers are provided so this is executable rather than asserted:
`read-completeness.mjs` implements only the ratified v1 rule;
`read-run-declaration.mjs` implements the deferred proposal. The key
names in the latter are one emitter's choice and are not ratified — what
the fixtures demonstrate is the behaviour of the rule, not the spelling.

These fixtures discriminate **readings**, not schema conformance. Per
SARIF §3.14.23 a capped run is non-conformant regardless of disclosure —
do not use these as a validation target.

## Reproduction

Binary used for the captures: built from skil-lock `main` at `c0ebb91`
with `-ldflags "-X main.version=0.2.3-9-gc0ebb91"`.

Case 3 — swallowed parse error (`swallowed-parse-error*.sarif.json`):

```sh
# complete run: one skill, locked, unchanged
mkdir -p complete/.claude/skills/hook-helper
cat > complete/.claude/skills/hook-helper/SKILL.md <<'EOF'
---
name: hook-helper
description: builds git hooks
---
# hook-helper

Run `git status` to inspect the tree.
EOF
(cd complete && skil-lock lock . && skil-lock ci . --format sarif > ../swallowed-parse-error-complete.sarif.json)

# swallowed run: two skills locked, then one corrupted so it fails to parse
cp -r complete swallowed
mkdir -p swallowed/.claude/skills/release-notes
cat > swallowed/.claude/skills/release-notes/SKILL.md <<'EOF'
---
name: release-notes
description: formats release notes
---
# release-notes

Plain prose guidance only.
EOF
(cd swallowed && skil-lock lock .)
# remove the required `name` field -> parse failure
cat > swallowed/.claude/skills/release-notes/SKILL.md <<'EOF'
---
description: formats release notes
---
# release-notes
EOF
(cd swallowed && skil-lock ci . --format sarif > ../swallowed-parse-error.sarif.json)
# stderr: warning: .claude/skills/release-notes/SKILL.md: ... missing a required field: "name"
# exit code: 0, and still 0 after the fix — warn mode does not block.
#
# Before skil-lock#44 the two JSON files were byte-identical. They now
# differ in run.properties.completeness (partial vs complete) and in the
# warning notification naming the skipped file.
```

Case 2 — detector-input bound (`narrowed-bound*.sarif.json`):

```sh
mkdir -p repo/.claude/skills/deploy-helper
cat > repo/.claude/skills/deploy-helper/SKILL.md <<'EOF'
---
name: deploy-helper
description: deployment helper
---
# deploy-helper

```bash
git status
```
EOF
(cd repo && skil-lock lock .)

# control: add a write with a 15-byte path -> SKL-FILE-WRITE, file_writes added
#   echo ok > /tmp/deploy.log
# bounded: the same added line with a 525-byte path
#   echo ok > /tmp/aaaa...a   (520 'a's)
# looksLikePath (internal/detector/paths/paths.go) rejects tokens > 512
# bytes before they are considered as paths, so the bounded run reports
# only a generic SKL-OTHER content_hash-modified note.
(cd repo && skil-lock ci . --format sarif)
```

## Case 4 — the clean run and the catalog convention

`clean-run-skil-lock.sarif.json`, read by
`tests/sarif/completeness-clean-run-catalog.test.mjs`.

**Read this first.** The test asserts on `lib/sarif/draft-validator.mjs`
and refers to `lib/sarif/artifact-digest.mjs`. Neither has a caller on
the scan path — each is imported only by its own test file, as
@aliksir disclosed in #24 when accepting this fixture. So the
assertions describe modules that are specified and tested and **not
wired into a run**, and nothing here is a statement about what a
`claude-code-skill-security-check` scan does today. That disclosure is
itself checked by the last `describe()` block in the test, which fails
the build if either module gains or loses callers, because a prose
note about wiring is exactly the claim this thread keeps finding to
have gone stale unnoticed.

**What it shows.** @aliksir reported that `validateRules` rejects an
empty rules array while a clean run has one, so the validator declares a
clean scan invalid. The fixture adds the part that changes where the fix
goes: **whether a clean run has an empty rules array is not a property
of the run, it is a property of the emitter's catalog convention.** A
full-catalog emitter publishes every rule it could report and a
fired-only emitter publishes the rules that did report; both produce the
same clean scan and hand the validator opposite inputs. Accepting `[]`
therefore does not finish the job — a validator that accepts it still
cannot tell a fired-only clean run from a full-catalog run whose catalog
failed to serialise. Only the run saying so separates them.

**Provenance, and what is constructed rather than captured.**
`clean-run-skil-lock.sarif.json` is real, unedited output of
[skills-lock/skil-lock](https://github.com/skills-lock/skil-lock) at
`0.2.4-2-g14d6d9d`, warn mode. Its `$schema` differs from the earlier
fixtures in this directory: through v0.2.4 skil-lock emitted a `$schema`
pointing into `oasis-tcs/sarif-spec` at branch `main`, a path the TC
moved in 2024, so the value 404'd in every release —
[skil-lock#46](https://github.com/skills-lock/skil-lock/pull/46) fixes it
to the OASIS-published artifact. The older captures here still carry the
dead value and are left as-is, since re-capturing them would change what
cases 2 and 3 pin.

The two catalogs the test compares are **constructed, not captured**,
and cannot be captured today: `validateRules` requires ATR or DRAFT rule
IDs, no emitter in the thread publishes an ATR-ID catalog yet, and a real
document with native IDs is rejected on ID format before the empty-set
question is reachable. The test asserts that rejection explicitly so the
boundary is visible rather than assumed.

### Reproduction (case 4)

```sh
mkdir -p repo/.claude/skills/hook-helper
cat > repo/.claude/skills/hook-helper/SKILL.md <<'SKILL'
---
name: hook-helper
description: builds git hooks
---
# hook-helper

Run `git status` to inspect the tree.
SKILL
(cd repo && skil-lock lock . && skil-lock ci . --format sarif > ../clean-run-skil-lock.sarif.json)
# exit code: 0, "PASS: no capability deltas"
# 6 rules in the catalog, 0 results, run.properties.completeness basis "complete"
```
