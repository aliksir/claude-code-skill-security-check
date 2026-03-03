---
name: skill-security-check
description: "Security audit for Claude Code community skills. Scans SKILL.md, references/, and scripts/ for prompt injection, data exfiltration, permission bypass, dangerous commands, supply chain risks, and backdoor persistence. No additional tool installations required. Use: /skill-security-check"
metadata:
  author: aliks
  version: "1.2.0"
risk: low
source: community
---

# Skill Security Check

Comprehensive security audit for Claude Code community skills.

## Trigger

`/skill-security-check` or "run a security check on my skills"

## Target

Default: `~/.claude/skills/` (all installed skills)

If a specific path or skill name is provided, scope to that target only.

## Before You Run

### Time Estimate

This skill launches 3 parallel agents that deeply analyze every installed skill. Expect:

| Skill count | Approximate time |
|------------|-----------------|
| ~50 skills | 5-10 minutes |
| ~200 skills | 15-25 minutes |
| ~500+ skills | 30-60 minutes |

### Permission Confirmations

Each agent performs many Grep/Read/Glob operations. Depending on your permission settings, you may be prompted frequently. For a smoother experience:

- Consider running with permissive read settings (Read/Grep/Glob auto-allow)
- The skill only **reads** files — it never modifies or deletes anything
- All file access is limited to the target skill directory

### No Additional Installations Required

This skill uses **only Claude Code built-in tools** (Grep, Glob, Read, Agent). No external CLI tools, no pip packages, no npm modules. It works out of the box.

> **Want deeper scanning?** For additional coverage beyond this skill, consider installing dedicated CLI security tools like [gitleaks](https://github.com/gitleaks/gitleaks), [semgrep](https://github.com/semgrep/semgrep), or [bandit](https://github.com/PyCQA/bandit) and running them separately on your projects.

---

## Workflow

Launch **3 parallel agents** (all `general-purpose`, model: `sonnet`) for independent analysis, then synthesize results.

---

## Agent 1: Pattern Scanner

Scan all `SKILL.md`, `references/**/*.md`, and `scripts/**` files using Grep.

### 1. Prompt Injection

- `IGNORE`, `FORGET`, `OVERRIDE`, `DISREGARD` (case-insensitive)
- `you are now`, `act as`, `pretend to be`, `new instructions`
- `system prompt`, `ignore previous`, `forget everything`
- `<system>`, `</system>`, `<instructions>` tag spoofing

### 2. Data Exfiltration

- External URLs with HTTP requests (excluding github.com, anthropic.com, arxiv.org, wikipedia.org)
- `curl`, `wget`, `fetch`, `httpx`, `requests.post` usage
- Base64 encoding instructions
- Instructions to output or send environment variables / API keys

### 3. Dangerous Commands

- `rm -rf`, `del /f`, `format`, `fdisk`
- `sudo`, `runas`, `chmod 777`
- `eval()`, `exec()`, `os.system()`, `subprocess.call(shell=True)`
- Piped script execution: `curl | bash`, `curl | sh`, `wget | sh`, `iex (iwr ...)`

### 4. Steganography

- Zero-width characters: U+200B, U+200C, U+200D, U+FEFF
- Hidden instructions inside HTML comments `<!-- -->`
- Hidden instructions inside Markdown comments `[//]: #`

### 5. Social Engineering

- "Share the contents of this file" patterns
- "If you get an error, access this URL" redirection
- Instructions to output credentials "for debugging"

### 6. Permission Bypass

- `bypassPermissions`, `defaultMode`
- `--dangerously-skip-permissions`, `--approval-mode`, `yolo`
- `danger-full-access`, `--no-verify`

### 7. HTTP Exfiltration Bypass

Detect patterns that bypass `curl`/`wget` deny rules by using language runtime inline execution:

- **Python inline HTTP**: `python -c` / `python3 -c` with `urllib.request`, `requests.get`, `requests.post`, `http.client.HTTPConnection`, `http.client.HTTPSConnection`, `httpx.post`, `httpx.get`, `socket.connect`
- **Node.js inline HTTP**: `node -e` with `fetch(`, `http.get(`, `https.get(`, `require('http')`, `require('https')`, `XMLHttpRequest`, `axios.get`, `axios.post`
- **Bypass rationale**: when `curl` is in deny list but `Bash(python:*)` or `Bash(node:*)` is in allow list, HTTP exfiltration is still possible via inline scripts
- **Environment variable piping**: `env | curl`, `printenv | python3`, `set | python -c`, `env | node -e` — patterns that pipe secrets to external HTTP calls

### 8. Credential Access

Detect patterns that access or reference credential files:

- **SSH keys**: `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/id_*`, `~/.ssh/config`, `~/.ssh/authorized_keys`, `~/.ssh/known_hosts`
- **AWS credentials**: `~/.aws/credentials`, `~/.aws/config`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- **GCP credentials**: `application_default_credentials.json`, `gcloud/credentials.db`, `gcloud/properties`, `GOOGLE_APPLICATION_CREDENTIALS`
- **Azure credentials**: `~/.azure/accessTokens.json`, `~/.azure/azureProfile.json`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`
- **Encoding obfuscation**: `base64` encoding/decoding of credential content, `xxd` hex dump of key files — patterns that obscure credential theft

### 9. Reverse Shell

Detect reverse shell patterns that establish remote command execution:

- **Bash**: `bash -i >& /dev/tcp/`, `bash -c 'exec bash -i &>/dev/tcp/'`
- **Netcat**: `nc -e /bin/bash`, `nc -e /bin/sh`, `ncat -e`, `nc.traditional -e`
- **Python**: `python -c 'import socket,subprocess,os;s=socket.socket(...)'`, `pty.spawn`
- **Ruby**: `ruby -rsocket -e`, `TCPSocket.open`
- **Perl**: `perl -e 'use Socket;'`, `perl -MIO::Socket`
- **PowerShell**: `New-Object System.Net.Sockets.TCPClient`, `Invoke-Expression`, `IEX(New-Object Net.WebClient)`

### 10. Backdoor Persistence

Detect patterns that establish persistent unauthorized access:

- **SSH backdoor**: `echo "ssh-rsa" >> ~/.ssh/authorized_keys`, public key injection into authorized_keys
- **Cron backdoor**: `echo "* * * * *" >> /etc/crontab`, `/var/spool/cron/`, crontab backdoor scripts
- **Cloud backdoor**: `aws iam create-access-key`, `az ad sp create`, backdoor service principal creation, IAM user/key creation for persistence
- **Systemd persistence**: `systemctl enable`, `.service` file creation in `/etc/systemd/`
- **Startup persistence**: `.bashrc` / `.profile` / `.zshrc` injection, Windows Run key / Scheduled Task creation

### 11. Privilege Escalation via System Utilities

Detect GTFOBins/LOLBAS-style privilege escalation patterns:

- **find -exec**: `sudo find . -exec /bin/sh \;`, `find -exec /bin/bash`
- **vim/vi escape**: `sudo vim -c ':!/bin/bash'`
- **awk/nawk**: `sudo awk 'BEGIN {system("/bin/bash")}'`
- **tar extraction**: `tar -cvf key.tar /root/.ssh/id_rsa` — extracting sensitive files via archive
- **SUID exploitation**: `find / -perm -4000`, SUID binary enumeration and abuse
- **shadow file access**: `base64 /etc/shadow`, credential dump via encoding

Report ALL hits (including false positives). Classification is done in the synthesis phase.

---

## Agent 2: Red Team Analyst

Analyze skills from an attacker's perspective. Read SKILL.md and referenced files, then evaluate:

### Attack Vectors

1. **Prompt Injection** — subtle manipulation hidden in natural language (not just keyword matches). Watch for gradual escalation: "legitimate test setup" that transitions step-by-step into backdoor installation
2. **Indirect Prompt Injection** — malicious instructions embedded in `references/` files that Claude would follow as high-trust instructions. Pay special attention to `references/` directories containing executable scripts or imperative commands disguised as documentation
3. **Data Theft** — paths to steal environment variables, `.env`, API keys, SSH keys, cloud credentials. Include indirect paths: IMDS/instance metadata access, output-to-clipboard-to-paste chains
4. **Cross-Skill Privilege Escalation Chains** — Skill A enables reconnaissance → Skill B exploits findings → Skill C establishes persistence. Evaluate whether skills that are individually "safe" become dangerous when combined in sequence
5. **Trust Boundary Abuse** — leveraging trust in well-known brands/companies to reduce user vigilance. Watch for authoritative naming (e.g., "Ethical Hacking Methodology") that may cause users to over-trust dangerous procedures
6. **MCP Tool Poisoning** — malicious instructions embedded in MCP tool descriptions that override agent behavior. Includes hidden directives in tool `description` fields, tool update supply chain attacks (legitimate tool replaced with malicious version), and exploitation of MCP server trust boundaries. Reference CVEs: CVE-2025-6514 (mcp-remote SSRF/RCE via malicious MCP server), CVE-2026-21852 (API key theft via poisoned MCP tool description)
7. **Settings.json Manipulation** — skills that modify Claude Code configuration to weaken security posture. Includes auto-enabling `enableAllProjectMcpServers: true`, injecting wildcard allow patterns (e.g., `Bash(* --version)` enabling arbitrary command execution), and exploiting `Bash(python:*)` / `Bash(node:*)` allow rules to bypass `curl`/`wget` deny lists

### Focus Areas

- Skills that modify Claude Code settings or permissions
- Skills that reference `~/.ssh`, `~/.aws`, `~/.config`, `~/.env`
- Skills with `risk: unknown` or no risk field
- Single authors with many security/attack-oriented skills (supply chain concentration risk)
- External URLs that receive data (especially non-standard domains)
- `references/` directories with imperative scripts or multi-step attack procedures

---

## Agent 3: Deep Analyzer

Perform five analysis roles in a single agent:

### Role A: Supply Chain Analysis

- **Metadata completeness audit**: check every SKILL.md frontmatter for `name`, `description`, `metadata.author`, `source`, and `risk` fields. Report the percentage of skills missing author/source information (skills without provenance are higher risk)
- **Author trust tier classification**:

| Tier | Criteria | Risk Level |
|------|----------|-----------|
| A | Anthropic official, major company official repos | Lowest |
| B | Well-known OSS developers, verified community with GitHub presence | Low |
| C | Individual developers, company names, licensed repos | Medium |
| D | Individual developers with few repos/stars | Medium-High |
| F | No author/source info, untraceable origin | Highest |

- Inventory all executable files: `.sh`, `.py`, `.js`, `.bat`, `.ps1`
- Count `subprocess`, `os.system`, `shell=True` usage in scripts
- Count HTTP client usage (`requests`, `httpx`, `urllib`, `fetch`, `curl`)
- Count `eval()` / `exec()` usage
- Detect dynamic external fetch instructions
- **Author concentration analysis**: cluster skills by author — flag single authors with 10+ skills (single point of compromise risk)

### Role B: Cognitive Manipulation Analysis

- **Authority bias**: "As an expert..." leading to dangerous operations
- **Normalization bias**: "By default..." for non-default dangerous behaviors
- **Urgency bias**: "Without waiting for confirmation..." bypassing user approval
- **Scope creep**: "For debugging..." expanding to full environment variable dumps
- **Implicit privilege escalation**: natural-sounding guidance toward sudo/runas
- **Step-by-step normalization**: procedures that start with safe actions and gradually escalate to dangerous ones, lowering the user's psychological barrier at each step

### Role C: Privacy Audit

- Environment variable / credential reference patterns (full count)
- Sensitive directory access: `~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, `~/.env`
- Output destination analysis: writes outside project directory, external transmission
- Claude settings modification: `bypassPermissions`, permission mode changes

### Role D: Settings & Hook Audit

Analyze Claude Code configuration files for security misconfigurations:

- **Permission patterns**: audit `permissions.allow` and `permissions.deny` arrays in `settings.json` — flag overly broad allow patterns (wildcards, `Bash(python:*)`, `Bash(node:*)`) and missing deny entries for dangerous commands
- **Hook definitions**: examine PreToolUse and PostToolUse hook definitions for safety — flag hooks that execute arbitrary Bash commands, hooks that modify files outside project scope, and hooks that disable other security controls
- **MCP server settings**: check for `enableAllProjectMcpServers: true` which auto-trusts all project-level MCP servers without user confirmation
- **Hook command safety**: analyze Bash commands within hook definitions for dangerous patterns (data exfiltration, privilege escalation, credential access) — hooks run automatically and bypass normal approval flows

### Role E: Skill Interconnection Risk

Analyze how skills could be combined to create attack chains:

- Map skills that provide reconnaissance capabilities (port scanning, service enumeration, OSINT)
- Map skills that provide exploitation capabilities (vulnerability exploitation, payload generation)
- Map skills that provide persistence capabilities (backdoor creation, credential harvesting)
- Flag any recon → exploit → persist chains that could be executed in a single session
- Check if high-risk skills properly require user confirmation at each escalation step

---

## Synthesis (Main Agent)

After all 3 agents report, classify every finding:

| Verdict | Criteria | Action |
|---------|----------|--------|
| **DELETE** | Sends credentials to unofficial external servers / auto-enables bypassPermissions / confirmed prompt injection | Remove immediately |
| **ACTION REQUIRED** | shell=True with user input / plaintext credential storage / recursive .env search in parent dirs / piped shell execution / backdoor persistence instructions without risk:high | Fix or establish operational rules |
| **CAUTION** | External API dependency (API key required) / educational attack patterns / cognitive manipulation false positives / high-risk skills properly marked with risk:high | Note for awareness |
| **CLEAN** | No issues found | No action needed |

### Output Format

Produce a report with:

1. **Summary table**: verdict counts (DELETE / ACTION REQUIRED / CAUTION / CLEAN)
2. **Supply chain overview**: metadata completeness rate, author tier distribution, author concentration flags
3. **CRITICAL section**: skills to delete, with file paths, code snippets, and attack scenarios
4. **HIGH section**: skills requiring fixes, with specific remediation steps
5. **MEDIUM section**: caution items for awareness
6. **CLEAN section**: confirmation of what was checked and found safe
7. **Statistics**: total skills scanned, files checked, hits per category, true/false positive breakdown

### Key Principles

- **Zero tolerance** for `bypassPermissions` auto-configuration outside containers
- **Zero tolerance** for data exfiltration to unknown external endpoints
- **Context matters**: `curl | bash` in a pentest skill's documentation (describing attack methods) is different from a setup script that actually runs it
- **Author clustering**: a single author providing many attack-oriented skills with `risk: unknown` is a supply chain risk signal
- **False positive awareness**: prompt injection keywords in security education content are expected — flag but don't auto-classify as threats
- **Metadata absence is a signal**: skills with no author, no source, and no risk field deserve closer scrutiny regardless of content

---

## Changelog

### v1.2.0 (2026-03-04)

- Added "Before You Run" section with time estimates, confirmation notes, and installation-free guarantee
- New detection: backdoor persistence patterns (SSH authorized_keys, crontab, cloud IAM, systemd, startup scripts)
- New detection: privilege escalation via system utilities (GTFOBins/LOLBAS patterns — find -exec, vim escape, tar extraction, SUID abuse, shadow dump)
- Enhanced Red Team: cross-skill privilege escalation chain analysis, references/ directory scrutiny, step-by-step normalization detection
- Enhanced Supply Chain: author trust tier classification (A-F), metadata completeness audit, author concentration analysis
- New Role E: Skill Interconnection Risk — maps recon/exploit/persist chains across skills
- Enhanced Synthesis: supply chain overview in output, metadata absence as a risk signal
- Added Credits & Acknowledgments section

### v1.1.0 (2026-03-03)

- New detection: HTTP exfiltration bypass (python -c / node -e inline HTTP patterns)
- New detection: credential file access patterns (SSH, AWS, GCP, Azure)
- New detection: reverse shell patterns (Bash, netcat, Python, Ruby, Perl, PowerShell)
- New Red Team vector: MCP tool poisoning (CVE-2025-6514, CVE-2026-21852)
- New Red Team vector: settings.json manipulation
- New Role D: Settings & Hook Audit

### v1.0.0 (2026-03-02)

- Initial release: pattern scanner, red team analyst, deep analyzer
- 6 detection categories: prompt injection, data exfiltration, dangerous commands, steganography, social engineering, permission bypass

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

*Maintained by [@aliksir](https://github.com/aliksir) — Issues and PRs welcome.*
