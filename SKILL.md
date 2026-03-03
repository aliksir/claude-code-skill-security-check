---
name: skill-security-check
description: "Security audit for Claude Code community skills. Scans SKILL.md, references/, and scripts/ for prompt injection, data exfiltration, permission bypass, dangerous commands, and supply chain risks. Use when you want to audit installed skills: /skill-security-check"
metadata:
  author: aliks
  version: "1.1.0"
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

Report ALL hits (including false positives). Classification is done in the synthesis phase.

---

## Agent 2: Red Team Analyst

Analyze skills from an attacker's perspective. Read SKILL.md and referenced files, then evaluate:

### Attack Vectors

1. **Prompt Injection** — subtle manipulation hidden in natural language (not just keyword matches)
2. **Indirect Prompt Injection** — malicious instructions embedded in `references/` files that Claude would follow
3. **Data Theft** — paths to steal environment variables, `.env`, API keys, SSH keys, cloud credentials
4. **Privilege Escalation Chains** — Skill A enables permissions → Skill B exploits them → dangerous operation
5. **Trust Boundary Abuse** — leveraging trust in well-known brands/companies to reduce user vigilance
6. **MCP Tool Poisoning** — malicious instructions embedded in MCP tool descriptions that override agent behavior. Includes hidden directives in tool `description` fields, tool update supply chain attacks (legitimate tool replaced with malicious version), and exploitation of MCP server trust boundaries. Reference CVEs: CVE-2025-6514 (mcp-remote SSRF/RCE via malicious MCP server), CVE-2026-21852 (API key theft via poisoned MCP tool description)
7. **Settings.json Manipulation** — skills that modify Claude Code configuration to weaken security posture. Includes auto-enabling `enableAllProjectMcpServers: true`, injecting wildcard allow patterns (e.g., `Bash(* --version)` enabling arbitrary command execution), and exploiting `Bash(python:*)` / `Bash(node:*)` allow rules to bypass `curl`/`wget` deny lists

### Focus Areas

- Skills that modify Claude Code settings or permissions
- Skills that reference `~/.ssh`, `~/.aws`, `~/.config`, `~/.env`
- Skills with `risk: unknown` or no risk field
- Single authors with many security/attack-oriented skills (supply chain risk)
- External URLs that receive data (especially non-standard domains)

---

## Agent 3: Deep Analyzer

Perform four analysis roles in a single agent:

### Role A: Supply Chain Analysis

- Inventory all executable files: `.sh`, `.py`, `.js`, `.bat`, `.ps1`
- Count `subprocess`, `os.system`, `shell=True` usage in scripts
- Count HTTP client usage (`requests`, `httpx`, `urllib`, `fetch`, `curl`)
- Count `eval()` / `exec()` usage
- Detect dynamic external fetch instructions
- Cluster skills by author — flag single authors with 10+ skills

### Role B: Cognitive Manipulation Analysis

- **Authority bias**: "As an expert..." leading to dangerous operations
- **Normalization bias**: "By default..." for non-default behaviors
- **Urgency bias**: "Without waiting for confirmation..." bypassing user approval
- **Scope creep**: "For debugging..." expanding to full environment variable dumps
- **Implicit privilege escalation**: natural-sounding guidance toward sudo/runas

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

---

## Synthesis (Main Agent)

After all 3 agents report, classify every finding:

| Verdict | Criteria | Action |
|---------|----------|--------|
| **DELETE** | Sends credentials to unofficial external servers / auto-enables bypassPermissions / confirmed prompt injection | Remove immediately |
| **ACTION REQUIRED** | shell=True with user input / plaintext credential storage / recursive .env search in parent dirs / piped shell execution | Fix or establish operational rules |
| **CAUTION** | External API dependency (API key required) / educational attack patterns / cognitive manipulation false positives | Note for awareness |
| **CLEAN** | No issues found | No action needed |

### Output Format

Produce a report with:

1. **Summary table**: verdict counts (DELETE / ACTION REQUIRED / CAUTION / CLEAN)
2. **CRITICAL section**: skills to delete, with file paths, code snippets, and attack scenarios
3. **HIGH section**: skills requiring fixes, with specific remediation steps
4. **MEDIUM section**: caution items for awareness
5. **CLEAN section**: confirmation of what was checked and found safe
6. **Statistics**: total skills scanned, files checked, hits per category, true/false positive breakdown

### Key Principles

- **Zero tolerance** for `bypassPermissions` auto-configuration outside containers
- **Zero tolerance** for data exfiltration to unknown external endpoints
- **Context matters**: `curl | bash` in a pentest skill's documentation (describing attack methods) is different from a setup script that actually runs it
- **Author clustering**: a single author providing many attack-oriented skills with `risk: unknown` is a supply chain risk signal
- **False positive awareness**: prompt injection keywords in security education content are expected — flag but don't auto-classify as threats
