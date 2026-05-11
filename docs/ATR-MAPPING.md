# ATR ↔ cssc Detection Categories Mapping

Cross-reference between [Agent Threat Rules (ATR) v2.1.2](https://github.com/Agent-Threat-Rule/agent-threat-rules) (338 rules / 10 threat categories) and `claude-code-skill-security-check` (cssc) v3.1.0 (26 detection categories).

**Generated**: 2026-05-11 (cssc v3.1.1 candidate, PoC scope)
**ATR snapshot**: v2.1.2 / 338 rules / 1,815 true positives / 1,671 true negatives / 656 evasion tests

## ATR 10 Threat Categories (with rule counts)

| Category | Rules | Severity highlight |
|----------|-------|--------------------|
| `prompt-injection` | 106 | Sigma-style injection attempts |
| `agent-manipulation` | 105 | Multi-turn manipulation, cross-agent attacks |
| `skill-compromise` | 35 | Malicious skill installation, supply chain |
| `context-exfiltration` | 33 | Sensitive context leakage |
| `tool-poisoning` | 28 | MCP/tool descriptor manipulation |
| `privilege-escalation` | 13 | Permission boundary violations |
| `model-abuse` | 10 | Excessive resource / inference loops |
| `excessive-autonomy` | 6 | Unbounded action sequences |
| `model-security` | (included in others) | Model integrity, alignment bypass |
| `data-poisoning` | 2 | Training/runtime data poisoning |

Severity breakdown: critical=120 / high=200 / medium=17 / low=1.
Maturity: experimental=300 / test=31 / stable=7.

## cssc 26 Detection Categories (from SKILL.md)

cssc covers the following 12 built-in YAML rule files + 12 additional analyzer-based detections + 2 hook-based runtime defenses:

**YAML rule packs (`core`)**:
prompt_injection / data_exfiltration / command_injection / hardcoded_secrets / obfuscation / social_engineering / supply_chain / unauthorized_tool_use / resource_abuse / api_hijacking / cloud_metadata / namespace_abuse

**Analyzer-based**:
static_analyzer / bytecode_analyzer / pipeline_analyzer / behavioral_analyzer / trigger_analyzer / llm_analyzer / meta_analyzer / virustotal_analyzer / aidefense_analyzer / namespace_analyzer / size_analyzer / temporal_analyzer

**Runtime hooks**:
MCP response inspector / Bash command validator / ghost file detector

## Mapping Matrix

### A. Overlap (both ATR and cssc cover)

| ATR Category | ATR Rules | cssc Equivalent | Overlap nature |
|---|---|---|---|
| `prompt-injection` | 106 | `prompt_injection` YAML pack + `static_analyzer` | Both cover IGNORE/OVERRIDE patterns; ATR has broader Sigma-style coverage |
| `agent-manipulation` | 105 | `social_engineering` + `meta_analyzer` (partial) | Partial overlap; ATR much deeper on multi-turn manipulation |
| `skill-compromise` | 35 | `supply_chain` + `namespace_abuse` + `namespace_analyzer` | cssc has typosquat focus; ATR adds malicious-install patterns |
| `context-exfiltration` | 33 | `data_exfiltration` + `cloud_metadata` | Strong overlap on HTTP/encoding/IMDS; ATR adds context-specific leakage |
| `tool-poisoning` | 28 | `unauthorized_tool_use` + MCP response inspector (hook) | Both address tool/permission manipulation; cssc has runtime block, ATR has detection patterns |
| `privilege-escalation` | 13 | `unauthorized_tool_use` (partial) | Partial overlap; ATR is broader on permission boundary violations |
| `model-abuse` | 10 | `resource_abuse` | Strong overlap on resource consumption / loop detection |
| `data-poisoning` | 2 | (none) | cssc does not cover training-data poisoning |

### B. Net New (ATR coverage, cssc gap — v3.2.0 candidates)

| ATR Category | ATR Rules | Justification for v3.2.0 `atr_analyzer` |
|---|---|---|
| `excessive-autonomy` | 6 | cssc has no equivalent for unbounded action sequences detection. ATR rules can be evaluated via `atr_analyzer` opt-in to extend cssc coverage. |
| `model-security` | (bundled) | cssc does not address model alignment bypass / output integrity. ATR contributes detection patterns. |
| `data-poisoning` | 2 | cssc focuses on skill-time, not training-time. ATR's 2 rules add training/runtime data poisoning awareness. |
| ATR deep `agent-manipulation` extensions | 105 - (overlap with social_engineering) | Multi-turn agent manipulation patterns. cssc's `social_engineering` and `meta_analyzer` cover authority/urgency bias but not session-level manipulation chains. |
| ATR CVE-mapped rules | 31 (rules with CVE) | cssc has no CVE traceability. ATR rules with explicit CVE mapping (e.g. CVE-2026-40933 Flowise) add identifiable threat-intelligence linkage. |

### C. cssc-only (cssc coverage, ATR does not address)

| cssc Category | Coverage | Reason ATR doesn't address |
|---|---|---|
| `hardcoded_secrets` | API keys / tokens / passwords in source | ATR focuses on agent runtime, not source code static analysis |
| `obfuscation` | Zero-width / steganography / Unicode homoglyphs | cssc-specific text-encoding obfuscation patterns |
| `api_hijacking` | `ANTHROPIC_BASE_URL` override / proxy injection / DNS / hosts | Claude Code–specific environment manipulation |
| `cloud_metadata` (full) | IMDS 169.254.169.254 / cloud token theft | Some overlap with ATR `context-exfiltration`, but cssc has dedicated cloud-credential focus |
| `bytecode_analyzer` | Python `.pyc` integrity | cssc skill-specific (Python pyc tampering) |
| `pipeline_analyzer` | Command pipeline taint | cssc skill-specific (shell pipeline) |
| `temporal_analyzer` | Conditional/delayed attack patterns via AST | cssc-specific time-bomb detection |
| `namespace_analyzer` | Levenshtein-based author/skill name similarity | cssc-specific typosquat algorithm |
| `size_analyzer` | File size anomaly (context window poisoning) | cssc-specific Claude Code attack surface |
| Runtime hooks (MCP inspector / Bash validator / ghost file detector) | Active blocking at runtime | ATR is detection-only, not runtime enforcement |
| `aidefense_analyzer` | Cisco AI Defense cloud integration | cssc-specific commercial integration |

## Conclusion / Recommendation for v3.2.0

The mapping reveals three actionable insights for the future v3.2.0 `atr_analyzer` opt-in implementation in `skill-scanner`:

1. **Net New value**: ATR brings clear gap-fill in `excessive-autonomy`, `model-security`, `data-poisoning`, deep multi-turn `agent-manipulation`, and CVE-mapped traceability. These are the strongest justification for adding `atr_analyzer` as an opt-in analyzer (similar to `aidefense_analyzer`).
2. **Overlap risk**: For `prompt-injection`, `data_exfiltration`, `tool-poisoning`, `model-abuse`, enabling both cssc native rules and ATR simultaneously may cause finding duplication. Recommend implementing FP-suppression / dedup logic in `atr_analyzer` based on rule pack origin.
3. **cssc-only retention**: cssc's `hardcoded_secrets`, `obfuscation`, `api_hijacking`, runtime hooks, and `bytecode_analyzer` cover threats outside ATR's scope. These remain cssc's unique value and should not be replaced by ATR.

False positive rate measurement on the 432 known-attack corpus is required before promoting `atr_analyzer` from PoC to GA — currently the corpus is not yet received, so empirical FP rate is pending.

## References

- ATR repo: https://github.com/Agent-Threat-Rule/agent-threat-rules
- ATR v2.1.2 (npm `agent-threat-rules`, published 2026-05-11)
- cssc v3.1.0 release report: `result/20260511_cssc-v3.1.0-release.md`
- cssc v3.1.1 (ATR integration PoC) plan: `plans/20260511_atr-integration-poc.md`
- Bundled ATR snapshot: `semgrep-rules/atr/`
