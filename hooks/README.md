# MCP Response Inspector Hook

Runtime hook that inspects MCP tool responses for prompt injection, dangerous commands, data exfiltration patterns, and hidden content.

## Why

MCP server responses are **untrusted external data** (FIDES: LOW). The same structural vulnerability that exists in cloned OSS backdoors — where AI follows existing patterns including malicious ones — applies to MCP responses. Without runtime inspection, injected instructions in MCP responses are treated as trusted data.

This hook provides a runtime defense layer that static analysis alone cannot cover.

## What it detects

| Category | Severity | Examples |
|----------|----------|---------|
| Prompt Injection | CRITICAL | `IGNORE previous instructions`, `you are now`, `<system>` tag spoofing |
| Dangerous Commands | HIGH | `rm -rf /`, `bypassPermissions`, `ANTHROPIC_BASE_URL=` override |
| Data Exfiltration | HIGH | `env \| curl`, credential file access, API key extraction |
| Suspicious URLs | MEDIUM | HTTP POST to unknown domains, reverse shell patterns |
| Hidden Content | HIGH | Zero-width characters, bidirectional override, HTML comment injection |
| Tool Redefinition | HIGH | `override tool`, `shadow tool`, same-name tool registration in response |
| Agent Infection | HIGH | `install skill`, `propagate to other`, `spawn agent` directives |
| Budget Drain | MEDIUM | `think step by step in extreme detail`, `repeat 999 times`, `enumerate all possible` |

## Install

### 1. Copy the hook file

```bash
# Create hooks directory if needed
mkdir -p ~/.claude/hooks/post_tool_use/

# Copy the hook
cp hooks/mcp-response-inspector.mjs ~/.claude/hooks/post_tool_use/
```

### 2. Add to settings.json

Add this entry to the `hooks.PostToolUse` array in `~/.claude/settings.json`:

```json
{
  "matcher": "mcp__",
  "hooks": [
    {
      "type": "command",
      "command": "node ~/.claude/hooks/post_tool_use/mcp-response-inspector.mjs",
      "timeout": 5
    }
  ]
}
```

### 3. Verify

The hook runs automatically on every MCP tool response. No restart required.

## Behavior

- **CRITICAL findings on untrusted MCP**: Blocks the response (exit code 2)
- **HIGH/MEDIUM findings**: Warns via stderr (visible to user), does not block
- **Trusted MCP prefixes** (`mcp__memory__`, etc.): Warns but never blocks
- **Non-MCP tools**: Skipped entirely (zero overhead)
- **Short responses** (< 20 chars): Skipped (false positive reduction)

## Customization

Edit the `TRUSTED_MCP_PREFIXES` array to add your known-safe MCP servers:

```javascript
const TRUSTED_MCP_PREFIXES = [
  'mcp__memory__',
  'mcp__your_trusted_server__',
];
```

## Limitations

- Pattern-based detection — sophisticated obfuscation may evade
- Does not validate semantic meaning (e.g., "delete all files" as natural language without command syntax)
- Complements but does not replace static analysis (`skill-scanner`) and policy-level controls (FIDES trust levels)

---

# Ghost File Detector Hook

PostToolUse hook that detects "ghost files" — a common AI-generated code anti-pattern where agents create similarly-named new files instead of modifying existing ones (e.g., `utils2.py` instead of editing `utils.py`).

## Why

AI coding agents have a documented tendency to create new files with suffixed names rather than modifying existing code. This leads to code duplication, dead files, and confusion. The hook catches this pattern at creation time and warns the user.

## What it detects

| Pattern | Example | Warning |
|---------|---------|---------|
| Numeric suffix | `utils2.py` when `utils.py` exists | Yes |
| `_new` suffix | `config_new.json` when `config.json` exists | Yes |
| `_copy` suffix | `handler_copy.ts` when `handler.ts` exists | Yes |
| `_backup` suffix | `main_backup.py` when `main.py` exists | Yes |
| `_old` suffix | `app_old.js` when `app.js` exists | Yes |
| Versioned suffix | `service_v2.go` when `service.go` exists | Yes |

## Install

### 1. Copy the hook file

```bash
cp hooks/ghost-file-detector.sh ~/.claude/hooks/post_tool_use/
chmod +x ~/.claude/hooks/post_tool_use/ghost-file-detector.sh
```

### 2. Add to settings.json

Add this entry to the `hooks.PostToolUse` array in `~/.claude/settings.json`:

```json
{
  "matcher": "Write",
  "hooks": [
    {
      "type": "command",
      "command": "bash ~/.claude/hooks/post_tool_use/ghost-file-detector.sh",
      "timeout": 3
    }
  ]
}
```

## Behavior

- **Warning only** — does not block file creation (the file may be intentional)
- Checks the same directory for a file matching the base name (without trailing numbers, `_new`, `_copy`, `_backup`, `_old`, `_tmp`, `_v*`)
- Non-Write tools are ignored (zero overhead)
- No dependencies — pure bash + jq

---

# Validate Bash Hook

PreToolUse hook that blocks dangerous Bash commands with a 9-tier defense system. Includes quote-aware false positive prevention.

## Why

AI coding agents execute Bash commands autonomously. Without guardrails, they can run destructive operations (`rm -rf /`, `git push --force`), exfiltrate data (`python -c "import requests; ..."`), or access credentials (`cat ~/.ssh/id_rsa`). This hook provides a defense layer that catches these patterns before execution.

## What it blocks

| Tier | Category | Severity | Examples |
|------|----------|----------|---------|
| 1 | System destruction | CRITICAL | `rm -rf /etc`, `format C:`, `del /f` |
| 2 | Git force operations | HIGH | `git push --force`, `git push origin main`, `git reset --hard` |
| 3 | Git mass staging | MEDIUM | `git add -A`, `git add .`, `git add --all` |
| 4 | Piped script execution | HIGH | `curl \| bash`, `wget \| sh` |
| 5 | HTTP exfiltration bypass | HIGH | `python -c "import requests"`, `node -e "fetch(...)"` |
| 6 | Credential access | HIGH | `cat ~/.ssh/id_rsa`, `cat ~/.aws/credentials` |
| 7 | Env variable exfiltration | HIGH | `env \| curl`, `printenv \| python` |
| 7.5 | Scan result exfiltration | MEDIUM | `curl --data-binary @report.json` |
| 8 | AWS/IaC destruction | HIGH | `aws s3api delete-bucket`, `terraform destroy`, `cdk destroy` |
| 9 | Reverse shells | CRITICAL | `bash -i >& /dev/tcp/`, `nc -e /bin/bash` |

## Quote-aware false positive prevention

The hook strips content inside `"..."` and `'...'` before checking Tier 1-4 and Tier 8-9 patterns. This prevents false positives when dangerous keywords appear as literal strings (e.g., in PR body text or echo statements).

Tier 5-7.5 intentionally inspect quoted content because inline code exfiltration (`python -c "import requests"`) and credential access patterns must be caught even inside quotes.

## Install

### 1. Copy the hook file

```bash
mkdir -p ~/.claude/hooks/pre_tool_use/
cp hooks/validate-bash.sh ~/.claude/hooks/pre_tool_use/
chmod +x ~/.claude/hooks/pre_tool_use/validate-bash.sh
```

### 2. Add to settings.json

Add this entry to the `hooks.PreToolUse` array in `~/.claude/settings.json`:

```json
{
  "matcher": "Bash",
  "hooks": [
    {
      "type": "command",
      "command": "bash ~/.claude/hooks/pre_tool_use/validate-bash.sh",
      "timeout": 5
    }
  ]
}
```

## Behavior

- **Deny with fix suggestion** — every blocked command includes an actionable alternative
- **Quote-aware** — literal strings in `"..."` / `'...'` don't trigger false positives (Tier 1-4, 8-9)
- **Non-Bash tools** — skipped entirely (zero overhead)
- **No dependencies** — pure bash + jq + grep + sed

## Customization

Add project-specific deny rules by appending new `if` blocks before `exit 0`:

```bash
if echo "$command_unquoted" | grep -qE 'your-pattern'; then
  deny "Description" "Suggested alternative"
fi
```

## License

MIT
