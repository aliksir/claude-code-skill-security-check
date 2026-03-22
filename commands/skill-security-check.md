---
description: Run security audit on installed Claude Code skills
---

# /skill-security-check

Security audit for Claude Code community skills. Scans installed skills for prompt injection, data exfiltration, permission bypass, dangerous commands, and 29 additional attack patterns.

## Trigger

`/skill-security-check` or "run a security check on my skills"

## Target

Default: `~/.claude/skills/` (all installed skills)

If a specific path or skill name is provided, scope to that target only.

## Two Modes

### Skill Mode (no installation required)

Launches **3 parallel Claude Code agents** for independent analysis, then synthesizes results:

- **Agent 1: Pattern Scanner** — Grep-based detection of 29 attack pattern categories
- **Agent 2: Red Team Analyst** — Attacker-perspective analysis (prompt injection, supply chain, MCP poisoning, etc.)
- **Agent 3: Deep Analyzer** — Supply chain, cognitive manipulation, privacy audit, settings/hook audit, temporal attack analysis

### CLI Mode

```bash
pip install skill-scanner
skill-scanner scan-all ~/.claude/skills/ --format markdown -o report.md
```

## Time Estimate

| Skill count | Approximate time |
|------------|-----------------|
| ~50 skills | 5-10 minutes |
| ~200 skills | 15-25 minutes |
| ~500+ skills | 30-60 minutes |

For faster scanning, use CLI mode: `skill-scanner scan-all ~/.claude/skills/`

## Permission Notes

Each agent performs many Grep/Read/Glob operations. For a smoother experience:

- Consider running with permissive read settings (Read/Grep/Glob auto-allow)
- The skill only **reads** files — it never modifies or deletes anything
- All file access is limited to the target skill directory

## Output

Results are classified into four verdicts:

| Verdict | Criteria |
|---------|----------|
| **DELETE** | Confirmed malicious — credential exfiltration, bypassPermissions auto-enable, confirmed prompt injection |
| **ACTION REQUIRED** | Dangerous patterns requiring fix or operational controls |
| **CAUTION** | Noteworthy but context-dependent findings |
| **CLEAN** | No issues found |

Report includes: summary table, supply chain overview, CRITICAL/HIGH/MEDIUM/CLEAN sections, and statistics.

## Runtime Defense Hooks

This plugin also installs three runtime hooks (via `hooks/hooks.json`):

- **`validate-bash.sh`** (PreToolUse/Bash) — blocks dangerous Bash commands before execution
- **`ghost-file-detector.sh`** (PostToolUse/Write) — detects AI anti-patterns on file write
- **`mcp-response-inspector.mjs`** (PostToolUse/mcp__) — inspects MCP responses for injected instructions

See [`hooks/README.md`](../hooks/README.md) for installation details.

---

*Maintained by [@aliksir](https://github.com/aliksir)*
