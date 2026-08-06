# Completeness fixtures (issue #24)

Two of the three discriminating cases accepted in
[#24](https://github.com/aliksir/claude-code-skill-security-check/issues/24):
a **detector-input bound** (case 2) and a **swallowed parse error**
(case 3). Case 1 (bounded run with disclosure) belongs to
prompt-defense-audit / Rul1an's emitter and is not here.

All four `.sarif.json` files are real, unedited output of
[skills-lock/skil-lock](https://github.com/skills-lock/skil-lock) at
`0.2.3+g5b443d9` (commit `5b443d9`), run in warn mode — the default
path, since warn is what you get with no `.skil-lock.yaml`. They pin
current behaviour, defects included; the emitter-side fixes (an
`invocations` block, the §4 failure channel, the completeness
declaration) are tracked in skil-lock itself and these fixtures should
*fail* to reflect reality once those land, at which point they get
regenerated.

These fixtures discriminate **readings** of the ratified v1 rule, not
schema conformance. Per SARIF §3.14.23 a capped run is non-conformant
regardless of disclosure — do not use these as a validation target.

## Reproduction

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
# exit code: 0. The two JSON files are byte-identical.
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
