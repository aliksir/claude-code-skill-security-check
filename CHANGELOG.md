# Changelog

All notable changes to `skill-security-check` are documented here.

---

## v2.4.0 (2026-03-16)

- **New: 4 Semgrep custom rules** (3 → 7 total)
  - `ssrf.yml`: Server-Side Request Forgery — fetch/axios/requests/urllib with user input, Express open redirect (CWE-918)
  - `sql-injection.yml`: SQL Injection via ORM bypass — Django raw()/extra(), SQLAlchemy text(), Sequelize query(), Prisma $queryRaw (CWE-89)
  - `weak-crypto.yml`: Weak cryptographic algorithms — MD5, SHA1, DES, RC4, Math.random() for security (CWE-327/328/330)
  - `insecure-deserialization.yml`: Insecure deserialization — pickle, yaml.load, Marshal, unserialize, eval(JSON.stringify) (CWE-502)
- **New: 4 detection patterns** (#23-#26)
  - #23: Tool Override / Shadow Attack — skill overriding existing tool definitions
  - #24: Whiteboard / Memory Injection — injecting commands into shared files (CLAUDE.md, MEMORY.md, whiteboard)
  - #25: Agent Spawn & Self-Replication — autonomous agent creation and propagation
  - #26: MCP Elicitation Abuse — credential harvesting and privilege escalation via Elicitation UI
- **New: Plugin manifest inspection** — `.claude-plugin/plugin.json` scanning for name impersonation, excessive permissions, undeclared hooks, metadata inconsistency
- **Enhanced: Role D** — `allowed-tools` audit for SKILL.md frontmatter (missing = Medium/High risk)
- **Enhanced: Red Team** — plugin manifest poisoning, namespace squatting via plugins, hook chain injection vectors
- **Enhanced: mcp-response-inspector.mjs** (v1.3.0) — Elicitation abuse detection (5 patterns, WARNING severity)

## v2.3.0 (2026-03-13)

- **New: Semgrep custom rules** (`semgrep-rules/`) — 7 rules for `/security-review` code change analysis
  - `angular-dom-xss.yml`: Angular `bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl()` detection (CWE-79)
  - `path-traversal.yml`: Zip Slip via `path.resolve()` + string concat, `fs.write*` with path concat, `path.join()` with untrusted variable (CWE-22)
  - `idor-auth-check.yml`: Express routes with auth middleware but no ownership check, `findById(req.params)` without owner filter (CWE-639)
- **Enhanced: `/security-review` workflow** — Added Step 2.5 (AI reasoning phase) for data flow analysis
  - Entry point identification (2-hop limit from changed code)
  - Authentication/authorization check (IDOR prevention)
  - Data flow tracing (input → validation → processing → output)
  - Structured output table in Step 4 report
- Semgrep standard + custom rules run in single invocation (`--config auto --config ~/.claude/semgrep-rules/`)
- Inspired by GitHub Security Lab's Taskflow Agent findings on OWASP Juice Shop

## v2.2.0 (2026-03-11)

- New detection: XOR/dynamic encoding obfuscation (ClawHavoc campaign patterns)
- New detection: agent-to-agent infection & lateral movement (P2P skill propagation)
- New detection: silent codebase exfiltration via DoD manipulation (Mitiga research)
- New detection: MCP tool redefinition/shadowing attacks
- New detection: API budget drain / overthinking DoS
- New detection: Auto Mode exploitation patterns
- New detection: multi-turn grooming (progressive privilege escalation)
- New Red Team vectors: DoD silent exfiltration, MCP tool shadowing, API budget drain
- New Deep Analyzer Role G: Auto Mode risk analysis
- Structural: Changelog extracted to CHANGELOG.md
- Structural: Credits moved to README.md
- Added LICENSE (MIT), .gitignore
- Added root README.md with disclaimer
- Updated mcp-response-inspector.mjs (v1.2.0): added tool_redefinition, agent_infection, budget_drain detection

## v2.1.3 (2026-03-09)

- **New: validate-bash.sh** (`hooks/validate-bash.sh`) — PreToolUse hook that blocks dangerous Bash commands
  - 9-tier defense: system destruction, git force push, git add -A, piped script execution, HTTP exfiltration, credential access, env exfiltration, AWS/IaC destruction, reverse shells
  - All deny messages include actionable fix suggestions (→ 代替: ...)
  - Quote-aware: literal strings inside `"..."` and `'...'` are excluded from Tier 1-4, 8-9 checks to prevent false positives (e.g., PR body text mentioning `git push --force`)
  - Tier 5-7.5 intentionally inspect quoted content (inline code HTTP exfiltration, credential access patterns must be caught even in quotes)

## v2.1.2 (2026-03-09)

- **New: Ghost File Detector Hook** (`hooks/ghost-file-detector.sh`) — PostToolUse hook that detects AI-generated "ghost files"
  - Catches common anti-pattern: creating `utils2.py` instead of editing `utils.py`
  - Detects numeric suffixes, `_new`, `_copy`, `_backup`, `_old`, `_v*` patterns
  - Warning-only (does not block) — the file may be intentional
  - Reference: AI-generated code creates ghost files in 90-100% of repositories (Harness Engineering Best Practices 2026)
- **Improved: validate-bash.sh error messages** — all deny messages now include actionable fix suggestions
  - Example: `git push --force は禁止 → 代替: git push --force-with-lease`
  - Principle: "Agents can ignore docs but cannot ignore linter errors" — error messages with fix examples guide correct behavior

## v2.1.1 (2026-03-09)

- **New: MCP Response Inspector Hook** (`hooks/mcp-response-inspector.mjs`) — runtime PostToolUse hook for MCP response inspection
  - Detects: prompt injection, dangerous commands, data exfiltration, suspicious URLs, hidden content (zero-width chars, bidi override)
  - CRITICAL findings on untrusted MCP → blocks response (exit 2)
  - Trusted MCP whitelist for false positive reduction
  - FIDES LOW enforcement at runtime

## v2.1.0 (2026-03-08)

- New detection: API endpoint hijacking (ANTHROPIC_BASE_URL override, proxy injection, DNS/hosts manipulation)
- New detection: namespace squatting / typosquatting (official prefix abuse, Levenshtein similarity)
- New detection: Unicode homoglyph & encoding attacks (Cyrillic homoglyphs, bidirectional override, IDN homograph)
- New detection: context window poisoning (oversized references, repetitive filler, instruction dilution)
- New Red Team vector: clipboard & output exfiltration chains
- New Red Team vector: cloud metadata / IMDS access (169.254.169.254, metadata.google.internal)
- New Red Team vector: symlink & path traversal attacks
- New Role F: temporal attack analysis (conditional triggers, progressive escalation, delayed payload, state file manipulation)
- Enhanced Role D: allowlist escape chain analysis (all runtime patterns: python/node/ruby/perl/npm/npx), API endpoint integrity check
- New CLI analyzers: `namespace_analyzer` (typosquat detection), `size_analyzer` (context poisoning), `temporal_analyzer` (delayed attacks)
- New YAML rule packs: `api_hijacking`, `cloud_metadata`, `namespace_abuse`
- Enhanced `obfuscation` rule pack: Unicode homoglyph patterns added

## v2.0.0 (2026-03-07)

- **CLI tool released**: `pip install skill-scanner` — standalone Python package
- 9 pluggable analyzers: static (YAML+YARA), bytecode, pipeline, behavioral (AST+taint), trigger, LLM judge, meta (FP filtering), VirusTotal, Cisco AI Defense
- YAML signature rule packs: 10 categories (prompt_injection, data_exfiltration, command_injection, hardcoded_secrets, obfuscation, social_engineering, supply_chain, unauthorized_tool_use, resource_abuse)
- Multiple output formats: summary, json, markdown, table, sarif (GitHub Code Scanning), html (interactive)
- Scan policy system: `--policy` presets and custom YAML policies
- `scan-all` command for batch scanning entire skill directories
- `interactive` wizard mode for guided scanning
- `generate-policy` / `configure-policy` for custom rule configuration
- `--fail-on-findings` / `--fail-on-severity` for CI/CD integration

## v1.2.0 (2026-03-04)

- Added "Before You Run" section with time estimates, confirmation notes, and installation-free guarantee
- New detection: backdoor persistence patterns (SSH authorized_keys, crontab, cloud IAM, systemd, startup scripts)
- New detection: privilege escalation via system utilities (GTFOBins/LOLBAS patterns — find -exec, vim escape, tar extraction, SUID abuse, shadow dump)
- Enhanced Red Team: cross-skill privilege escalation chain analysis, references/ directory scrutiny, step-by-step normalization detection
- Enhanced Supply Chain: author trust tier classification (A-F), metadata completeness audit, author concentration analysis
- New Role E: Skill Interconnection Risk — maps recon/exploit/persist chains across skills
- Enhanced Synthesis: supply chain overview in output, metadata absence as a risk signal
- Added Credits & Acknowledgments section

## v1.1.0 (2026-03-03)

- New detection: HTTP exfiltration bypass (python -c / node -e inline HTTP patterns)
- New detection: credential file access patterns (SSH, AWS, GCP, Azure)
- New detection: reverse shell patterns (Bash, netcat, Python, Ruby, Perl, PowerShell)
- New Red Team vector: MCP tool poisoning (CVE-2025-6514, CVE-2026-21852)
- New Red Team vector: settings.json manipulation
- New Role D: Settings & Hook Audit

## v1.0.0 (2026-03-02)

- Initial release: pattern scanner, red team analyst, deep analyzer
- 6 detection categories: prompt injection, data exfiltration, dangerous commands, steganography, social engineering, permission bypass
