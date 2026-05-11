# ATR (Agent Threat Rules) — bundled

This directory bundles the [Agent Threat Rules (ATR)](https://github.com/Agent-Threat-Rule/agent-threat-rules) detection rule collection as a **reference resource** for `claude-code-skill-security-check` users and downstream tooling.

## Contents

| Path | Description | Source |
|------|-------------|--------|
| `rules/` | 338 ATR YAML detection rules across 10 threat categories | ATR v2.1.2 `rules/` (bundled) |
| `LICENSE` | ATR MIT License (Copyright (c) 2026 ATR Contributors) | ATR v2.1.2 `LICENSE` |
| `stats.txt` | `atr stats` output snapshot (rule counts, categories, severity, maturity, detection tier) | Generated 2026-05-11 |
| `splunk-queries.spl` | Splunk SPL queries converted from 338 ATR rules via `atr convert splunk` | Generated 2026-05-11 |

## Bundled ATR Version

- **ATR v2.1.2** (npm `agent-threat-rules`, MIT License, published 2026-05-11)
- Upstream: https://github.com/Agent-Threat-Rule/agent-threat-rules
- Snapshot: 338 rules / 1,815 true positives / 1,671 true negatives / 656 evasion tests

## Why bundled?

- **No installation required for cssc users.** ATR YAML rules and queries ship with cssc; users do not need to run `npm install -g agent-threat-rules`.
- **Static reference resource.** ATR rules are not evaluated by the cssc skill mode or hooks at runtime. They are documentation / reference for security review workflows.
- **Future expansion anchor.** This directory is the **anticipated reference point** for the planned v3.2.0 `atr_analyzer` in the `skill-scanner` Python package (separate repo).

## How to update

When ATR releases a new version (e.g. v2.2.0):

```bash
# 1. Update ATR globally
npm install -g agent-threat-rules@latest

# 2. Refresh bundled rules
cp -r "$(npm root -g)/agent-threat-rules/rules" semgrep-rules/atr/

# 3. Refresh LICENSE (in case it changed)
cp "$(npm root -g)/agent-threat-rules/LICENSE" semgrep-rules/atr/LICENSE

# 4. Refresh stats and splunk export
atr stats | sed 's/\x1b\[[0-9;]*m//g' > semgrep-rules/atr/stats.txt
atr convert splunk --output semgrep-rules/atr/splunk-queries.spl

# 5. Verify file count and rule count
find semgrep-rules/atr/rules -name "*.yaml" -o -name "*.yml" | wc -l
grep "Total rules:" semgrep-rules/atr/stats.txt

# 6. Update cssc CHANGELOG.md and docs/ATR-MAPPING.md as needed
```

## Stability contract for downstream consumers

This directory's layout — `rules/<category>/*.yaml`, `LICENSE`, `stats.txt`, `splunk-queries.spl` — is the **anticipated stable interface** for the v3.2.0 `atr_analyzer` implementation in `skill-scanner`. Changes to file names, directory structure, or YAML schema in this bundle should be coordinated with the downstream consumer to avoid breaking the implicit contract.

If `atr_analyzer` adopts a different ATR consumption strategy (e.g., dynamic install at runtime instead of bundled snapshot), this README should be updated to reflect that decision.

**Note on directory vs. tag alignment**: The `rules/model-security/` subdirectory contains rules whose internal `tags.category` is `model-abuse` or `data-poisoning` (3 files: ATR-2026-00072, 00073, 00433). Directory names do not always match the internal category tag. The `atr stats` output groups by `tags.category`, which is why `stats.txt` lists 9 categories but `rules/` contains 10 directories. Downstream consumers should rely on the internal `tags.category` field rather than directory names.

## License attribution

ATR rules are MIT-licensed by ATR Contributors. The full license text is in `LICENSE`. cssc itself is also MIT-licensed, so the licenses are compatible.

When redistributing cssc with this bundle, retain the `LICENSE` file in place.

## Not generic-regex

Note: Earlier ATR marketing materials referenced a `generic-regex` export format. The ATR v2.1.2 CLI implements `convert splunk` and `convert elastic` only; there is no `convert generic-regex` subcommand. Patterns are embedded in the YAML rule files under `rules/`. See `splunk-queries.spl` for the converted form usable in SIEM platforms.
