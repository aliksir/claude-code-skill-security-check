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

## License

MIT
