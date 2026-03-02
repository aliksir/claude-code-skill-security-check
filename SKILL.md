---
name: skill-security-check
description: "Security audit for Claude Code community skills. Scans SKILL.md, references/, and scripts/ for prompt injection, data exfiltration, permission bypass, dangerous commands, and supply chain risks. Use when you want to audit installed skills: /skill-security-check"
metadata:
  author: aliks
  version: "1.0.0"
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

### Focus Areas

- Skills that modify Claude Code settings or permissions
- Skills that reference `~/.ssh`, `~/.aws`, `~/.config`, `~/.env`
- Skills with `risk: unknown` or no risk field
- Single authors with many security/attack-oriented skills (supply chain risk)
- External URLs that receive data (especially non-standard domains)

---

## Agent 3: Deep Analyzer

Perform three analysis roles in a single agent:

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
