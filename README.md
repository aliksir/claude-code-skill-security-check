# Skill Security Check

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg) ![Version](https://img.shields.io/badge/version-2.3.0-blue.svg)

A comprehensive security audit tool for Claude Code community skills. Combines a multi-agent skill mode (no installation required) with a standalone CLI tool (`skill-scanner`) to detect malicious patterns, supply-chain risks, and runtime threats in `.md` skill files.

---

> **Note**: This is a personal project and may produce false positives or miss certain threats.
> It is provided as-is without warranty. Use it as one layer of your security review process,
> not as a sole source of truth.

> **注意**: 本ツールは個人開発のプロジェクトです。誤検知（false positive）や検出漏れ（false negative）が
> 発生する可能性があります。セキュリティレビューの一助としてご利用ください。
> 本ツールの結果のみに依拠した判断は推奨しません。

---

## Features

- **22 detection categories** — prompt injection, data exfiltration, credential access, reverse shell, privilege escalation, and more
- **3 parallel scanning agents** — Pattern Scanner, Red Team Analyst, and Deep Analyzer run concurrently for faster, more thorough coverage
- **Runtime defense hooks** — MCP response inspector, Bash command validator, and ghost file detector protect against live threats
- **AWS IAM policy templates** — least-privilege templates for read-only and dev/deploy Claude Code environments
- **Semgrep custom rules** — 7 rules for Angular DOM XSS, path traversal/Zip Slip, and IDOR detection in code reviews
- **CLI tool** (`skill-scanner`) — YAML/YARA rule engine, AST-level analysis, optional LLM and VirusTotal integration

---

## Quick Start

### Skill Mode (no installation)

```
/skill-security-check
```

Runs directly inside Claude Code. Three agents scan your skills directory in parallel and produce a structured threat report.

### CLI Mode

```bash
pip install skill-scanner
skill-scanner scan-all ~/.claude/skills/ --format markdown -o report.md
```

---

## Update Checker

Check for new versions of Skill Security Check:

```bash
# Manual check (uses 24-hour cache)
bash updater/check-update.sh

# Force immediate check
bash updater/check-update.sh --force
```

You can also enable automatic checks at Claude Code session start via a SessionStart hook. See [updater/README.md](updater/README.md) for installation instructions.

---

## Project Structure

```
├── SKILL.md                          # Skill definition (detection patterns & agent workflow)
├── CHANGELOG.md                      # Version history
├── hooks/
│   ├── README.md                    # Hook installation & configuration guide
│   ├── mcp-response-inspector.mjs   # Runtime MCP response inspection
│   ├── validate-bash.sh             # Dangerous command prevention
│   └── ghost-file-detector.sh       # AI ghost file detection
├── semgrep-rules/
│   ├── angular-dom-xss.yml          # Angular bypassSecurityTrust* detection
│   ├── path-traversal.yml           # Zip Slip / path traversal patterns
│   └── idor-auth-check.yml          # IDOR preliminary detection
├── updater/
│   ├── README.md                    # Update checker setup guide
│   └── check-update.sh              # Version check script (manual or SessionStart hook)
└── iam-policy-template/
    ├── README.md                    # IAM policy usage guide
    ├── claude-code-readonly.json    # Read-only AWS policy
    └── claude-code-dev-deploy.json  # Dev/deploy AWS policy
```

---

## Detection Categories

| # | Category | Severity |
|---|----------|----------|
| 1 | Prompt Injection | CRITICAL |
| 2 | Data Exfiltration | HIGH |
| 3 | Dangerous Commands | HIGH |
| 4 | Steganography | HIGH |
| 5 | Social Engineering | HIGH |
| 6 | Permission Bypass | HIGH |
| 7 | HTTP Exfiltration Bypass | HIGH |
| 8 | Credential Access | HIGH |
| 9 | Reverse Shell | HIGH |
| 10 | Backdoor Persistence | HIGH |
| 11 | Privilege Escalation | HIGH |
| 12 | API Hijacking | MEDIUM-HIGH |
| 13 | Namespace Squatting | MEDIUM-HIGH |
| 14 | Unicode Homoglyph | MEDIUM-HIGH |
| 15 | Context Window Poisoning | MEDIUM-HIGH |
| 16 | XOR Obfuscation | MEDIUM |
| 17 | Agent Infection | HIGH |
| 18 | Silent Exfiltration | HIGH |
| 19 | MCP Redefinition | MEDIUM-HIGH |
| 20 | API Budget Drain | MEDIUM |
| 21 | Auto Mode Abuse | MEDIUM-HIGH |
| 22 | Multi-turn Grooming | HIGH |

---

## Runtime Defense Hooks

Three hooks integrate with Claude Code's hook system to block threats at runtime. See [hooks/README.md](hooks/README.md) for installation and configuration.

| Hook | Description |
|------|-------------|
| `mcp-response-inspector.mjs` | Inspects MCP tool responses for embedded prompt injection and exfiltration payloads before they reach the agent |
| `validate-bash.sh` | Intercepts Bash commands and blocks patterns matching `curl \| bash`, `rm -rf /`, `bypassPermissions`, and other Tier 1 dangerous operations |
| `ghost-file-detector.sh` | Detects AI-generated "ghost files" — similarly-named copies (e.g., `utils2.py`) created instead of editing the original, a common AI coding anti-pattern |

---

## Credits & Acknowledgments

This skill was built on lessons learned from auditing 575+ community skills. We are grateful to the following projects and their authors whose work informed our detection patterns:

### Community Skill Authors

- **[zebbern/claude-code-guide](https://github.com/zebbern/claude-code-guide)** — 23 penetration testing and security skills that directly informed our detection categories for credential access, reverse shells, privilege escalation chains, and backdoor persistence. These skills are educational tools for authorized security testing, and their explicit documentation of attack techniques helped us understand what patterns to detect. Thank you for the rapid response to our risk classification request (Issue #11).

- **[raintree-claude-tools](https://github.com/raintreeinc/raintree-claude-tools)** (formerly `anthropic/`) — claude-hook-builder and claude-settings-expert. The settings-expert skill's explicit "bypassPermissions is dangerous" documentation is a model for responsible skill design. The namespace discussion (Issue #492 on anthropics/skills) helped us refine trust boundary abuse detection.

- **[trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer)** — The devcontainer security discussion (Issue #28) about bypassPermissions auto-configuration outside containers was the catalyst for our Permission Bypass detection category.

- **[anthropics/skills](https://github.com/anthropics/skills)** — The official Claude Code skills registry. Our namespace protection discussion (Issue #492) helped shape the Trust Boundary Abuse detection vector.

### Security Research & Tools

- **[carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)** (LinPEAS/WinPEAS) — Referenced in multiple security skills. The `curl | sh` pattern for linpeas.sh was a key example that informed our piped script execution detection.

- **[GTFOBins](https://gtfobins.github.io/)** — The definitive reference for Unix binary exploitation techniques. Our privilege escalation via system utilities detection (Category 11) is directly informed by GTFOBins patterns.

- **[LOLBAS Project](https://lolbas-project.github.io/)** — Living Off The Land Binaries and Scripts for Windows. Complements GTFOBins for Windows-side detection patterns.

- **[Zenn article: Claude Code/MCP Security Guide](https://zenn.dev/ytksato/articles/057dc7c981d304)** by DPL — Practical security hardening guide that informed our HTTP exfiltration bypass detection and settings.json audit patterns.

### Detection Pattern References

- **MITRE ATT&CK Framework** — Tactics, Techniques, and Procedures (TTPs) referenced in our Red Team analysis vectors, especially T1098 (Account Manipulation), T1059 (Command & Scripting Interpreter), and T1071 (Application Layer Protocol).

- **OWASP** — Prompt injection and indirect prompt injection categories draw from OWASP's LLM Top 10 (2025).

### Special Thanks

Thank you to all community skill authors — including the many whose work we scanned without incident. The Claude Code skill ecosystem grows stronger when we look out for each other. If this tool flags your skill, it is not an accusation; it is an invitation to make the ecosystem safer together.

---

## Contributing

Issues and pull requests are welcome.

- [Open an issue](https://github.com/aliksir/claude-code-skill-security-check/issues)
- Fork the repo, make your changes, and submit a PR

---

## License

MIT — see [LICENSE](LICENSE)
