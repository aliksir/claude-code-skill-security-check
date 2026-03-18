---
name: skill-security-check
description: "Security audit for Claude Code community skills. Scans SKILL.md, references/, and scripts/ for prompt injection, data exfiltration, permission bypass, dangerous commands, supply chain risks, backdoor persistence, API endpoint hijacking, namespace squatting, Unicode homoglyph attacks, context window poisoning, and temporal attack patterns. Can be used as a Claude Code skill (agent-based) or as a standalone CLI tool (skill-scanner). Use: /skill-security-check"
metadata:
  author: aliks
  version: "2.5.0"
risk: low
source: community
---

# Skill Security Check

Comprehensive security audit for Claude Code community skills.

Available in two modes:
- **Skill mode**: 3 parallel Claude Code agents (no installation required)
- **CLI mode**: `skill-scanner` Python package with YAML/YARA rules, AST analysis, and optional LLM/VirusTotal/AI Defense integration

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

For faster scanning, use the CLI tool: `skill-scanner scan-all ~/.claude/skills/`

### Permission Confirmations

Each agent performs many Grep/Read/Glob operations. Depending on your permission settings, you may be prompted frequently. For a smoother experience:

- Consider running with permissive read settings (Read/Grep/Glob auto-allow)
- The skill only **reads** files — it never modifies or deletes anything
- All file access is limited to the target skill directory

### No Additional Installations Required (Skill Mode)

The skill mode uses **only Claude Code built-in tools** (Grep, Glob, Read, Agent). No external CLI tools, no pip packages, no npm modules. It works out of the box.

> **Want deeper scanning?** Install the CLI tool for YAML/YARA rule-based detection, AST analysis, and optional integrations:
> ```bash
> pip install skill-scanner
> skill-scanner scan-all ~/.claude/skills/ --format markdown -o report.md
> ```

---

## CLI Tool: skill-scanner

> Note: The CLI tool (`skill-scanner`) has its own release cycle on PyPI, separate from this skill's version.

### Installation

```bash
pip install skill-scanner
```

### Analyzers

| Analyzer | Type | Description |
|----------|------|-------------|
| `static_analyzer` | Default | Pattern-based detection using YAML + YARA rules |
| `bytecode_analyzer` | Default | Python .pyc integrity verification |
| `pipeline_analyzer` | Default | Command pipeline taint analysis |
| `behavioral_analyzer` | Opt-in | Static dataflow analysis (AST + taint tracking) |
| `trigger_analyzer` | Opt-in | Detects overly generic skill descriptions |
| `llm_analyzer` | Opt-in | Semantic analysis using LLMs as judges |
| `meta_analyzer` | Opt-in | Second-pass LLM false-positive filtering & prioritization |
| `virustotal_analyzer` | Opt-in | Hash-based malware detection via VirusTotal API |
| `aidefense_analyzer` | Opt-in | Cisco AI Defense cloud-based threat detection |
| `namespace_analyzer` | Default | Skill name/author similarity check (Levenshtein distance) for typosquat detection |
| `size_analyzer` | Default | File size anomaly detection for context window poisoning |
| `temporal_analyzer` | Opt-in | Conditional/delayed attack pattern detection via AST analysis |

### Detection Rule Packs

Built-in YAML signature packs (`core` pack):

| Rule File | Coverage |
|-----------|----------|
| `prompt_injection` | IGNORE/OVERRIDE/system prompt spoofing, tag injection |
| `data_exfiltration` | External HTTP, env var piping, base64 encoding |
| `command_injection` | rm -rf, eval/exec, piped script execution, reverse shells |
| `hardcoded_secrets` | API keys, tokens, passwords in source |
| `obfuscation` | Zero-width characters, steganography, encoding tricks, Unicode homoglyphs |
| `social_engineering` | Authority/urgency/normalization bias patterns |
| `supply_chain` | Missing metadata, author concentration, dynamic fetch |
| `unauthorized_tool_use` | bypassPermissions, permission mode changes, settings manipulation |
| `resource_abuse` | Crypto mining, excessive resource consumption |
| `api_hijacking` | ANTHROPIC_BASE_URL override, proxy injection, DNS/hosts manipulation |
| `cloud_metadata` | IMDS access (169.254.169.254), cloud metadata service token theft |
| `namespace_abuse` | Official namespace squatting, typosquatting, authority prefix abuse |

### Usage Examples

```bash
# Scan a single skill
skill-scanner scan ~/.claude/skills/my-skill/

# Scan all skills with markdown report
skill-scanner scan-all ~/.claude/skills/ --format markdown -o report.md

# Deep scan with behavioral analysis + LLM judge
skill-scanner scan ~/.claude/skills/my-skill/ --use-behavioral --use-llm

# CI/CD integration (fail on findings)
skill-scanner scan-all ~/.claude/skills/ --format sarif --fail-on-findings

# HTML interactive report
skill-scanner scan-all ~/.claude/skills/ --format html -o report.html

# Custom scan policy
skill-scanner scan ~/.claude/skills/my-skill/ --policy strict

# List available analyzers
skill-scanner list-analyzers
```

### Output Formats

`summary` (default), `json`, `markdown`, `table`, `sarif` (GitHub Code Scanning), `html` (interactive report)

---

## Skill Mode Workflow

Launch **3 parallel agents** (all `general-purpose`, model: `sonnet`) for independent analysis, then synthesize results.

---

## Agent 1: Pattern Scanner

Scan all `SKILL.md`, `references/**/*.md`, and `scripts/**` files using Grep.

### Plugin Manifest Inspection (.claude-plugin/plugin.json)

If the target contains a `.claude-plugin/plugin.json` manifest, additionally check:
- **Name impersonation**: Plugin name mimicking official namespaces (`anthropic-*`, `claude-*`, `official-*`)
- **Excessive permissions**: Hooks that request `Bash` or `Write` without clear justification
- **Undeclared hooks**: Hook files present in `hooks/` directory but not referenced in manifest
- **Metadata inconsistency**: Version, author, or description mismatch between plugin.json and SKILL.md
- **Settings override**: `settings.json` that changes agent or model without user awareness

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

### 12. API Endpoint Hijacking

Detect patterns that redirect Claude API calls to attacker-controlled servers:

- **Environment variable override**: `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_BASE`, `OPENAI_BASE_URL`, `api_base=`, `base_url=` — overriding API endpoints to intercept all conversations and API keys
- **SDK configuration**: `Anthropic(base_url=`, `OpenAI(base_url=`, `httpx.Client(base_url=` — programmatic API endpoint redirection
- **Proxy injection**: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy=`, `https_proxy=` — man-in-the-middle via proxy configuration
- **DNS/hosts manipulation**: `/etc/hosts`, `C:\Windows\System32\drivers\etc\hosts` modification to redirect api.anthropic.com
- **Attack scenario**: attacker sets `ANTHROPIC_BASE_URL` to their server → all API calls (including API key in headers) are forwarded → full conversation and credential theft

### 13. Namespace Squatting / Typosquatting

Detect skills that impersonate official or well-known sources:

- **Official namespace abuse**: skill name or `metadata.author` containing `anthropic`, `anthropics`, `claude-official`, `official-claude`, `openai` when `source: community`
- **Typosquatting**: Levenshtein distance ≤ 2 from known official skill names or popular community skill names
- **Authority prefix abuse**: `verified-`, `official-`, `trusted-`, `certified-` prefixes in skill names
- **Brand impersonation in descriptions**: descriptions claiming "official", "endorsed by Anthropic", "recommended by Claude" without verifiable source
- **Context**: the anthropics/skills#492 namespace discussion showed that `anthropic/` prefix in skill naming can mislead users into trusting unverified skills

### 14. Unicode Homoglyph & Encoding Attacks

Detect visual deception beyond zero-width characters:

- **Cyrillic/Greek homoglyphs in URLs and paths**: `а` (U+0430) vs `a` (U+0061), `о` (U+043E) vs `o` (U+006F), `е` (U+0435) vs `e` (U+0065) — visually identical characters in different Unicode blocks that make malicious URLs appear legitimate
- **Bidirectional override**: U+202E (Right-to-Left Override), U+202D (Left-to-Right Override), U+2066-U+2069 (isolate controls) — can reverse displayed text to hide true file extensions or command structure
- **Confusable domain names**: IDN homograph attacks in URLs (e.g., `аnthropic.com` with Cyrillic `а`)
- **Encoded payloads**: `\x`, `\u`, `%xx` sequences that decode to dangerous commands at runtime

### 15. Context Window Poisoning

Detect attempts to overflow the context window to push out safety instructions:

- **Abnormally large reference files**: `references/` files exceeding 50KB — legitimate documentation rarely needs this much content; oversized files may be designed to consume context budget and push out CLAUDE.md safety rules
- **Repetitive filler text**: large blocks of repeated or near-identical text (entropy analysis) that serve no informational purpose
- **Instruction dilution**: patterns where large volumes of benign-looking text surround a small malicious payload, reducing the likelihood of detection by both humans and LLMs
- **Multi-file bloat**: skills with 20+ reference files that collectively exceed reasonable documentation needs

### 16. XOR/Dynamic Encoding Obfuscation

Detect static analysis evasion techniques used in campaigns such as ClawHavoc:

- `xor`, `^=`, `bytes([a ^ b for` — XOR operations for payload reconstruction
- `chr(ord(` / `String.fromCharCode` — dynamic string assembly from character codes
- `eval(bytes(`, `exec(bytes(` — dynamic code execution from byte sequences
- Base85 (`b85decode`) / Base32 (`b32decode`) — uncommon encodings (non-Base64)
- `compile(`, `marshal.loads(` — dynamic loading of Python bytecode

### 17. Agent-to-Agent Infection & Lateral Movement

Detect P2P infection exploiting automated collaboration features:

- `skill install`, `skill add` — instructions to auto-install other skills
- `collaborate with`, `invoke agent`, `spawn agent` — automated inter-agent invocation
- Instructions to auto-deploy to other environments ("install this in all your projects", etc.)
- `spread`, `propagate`, `replicate` — patterns suggesting self-replication

### 18. Silent Codebase Exfiltration via DoD Manipulation

Detect Definition of Done manipulation to justify sending out entire codebases:

- `do not commit until all tasks complete` — delaying commits to wait for exfiltration completion
- `read all files in`, `aggregate codebase`, `collect all source` — bulk codebase reading
- `find . -name "*.py" -exec cat`, `find . -type f` — recursive file collection
- `backup`, `archive`, `snapshot` combined with external URL transmission

### 19. MCP Tool Redefinition Attack

Detect tool shadowing when multiple MCP servers run in the same environment:

- Definitions of `tool_name` / `function_name` identical to existing tools
- `override`, `replace`, `shadow` combined with tool definitions
- Instructions for dynamic modification of MCP server settings

### 20. API Budget Drain (DoS)

Detect intentional token consumption as an API cost attack:

- `think step by step in extreme detail about every possible` — excessive thinking induction
- Instructions for infinite loops or recursive self-reference
- Injecting massive context (instructing unnecessary reading of large numbers of files)
- `repeat`, `enumerate all`, `list every possible` — exhaustive enumeration instructions

### 21. Auto Mode Exploitation

Detect exploitation of autonomous permission decision weaknesses:

- `this will be automatically approved` — spoofing automatic approval
- `no confirmation needed`, `skip approval` — instructions to skip approval
- Procedures written assuming Auto Mode will execute dangerous operations without human confirmation

### 22. Multi-Turn Grooming

Detect gradual privilege escalation across multiple sessions:

- `Phase 1: setup`, `Phase 2: configure`, `Phase 3: deploy` — phased escalation
- Patterns where first invocation is benign, subsequent invocations execute dangerous operations
- `if first_run`, `if returning_user` — branching based on invocation count
- Trust building followed by privilege escalation (showing safe operations first, then the actual payload)

### 23. Tool Override / Shadow Attack

スキルが既存ツールの定義を上書き・シャドウイングするパターン:
- `override`, `replace`, `redefine`, `shadow` + ツール名（Read, Write, Edit, Bash等）
- ツール定義の再宣言（`"name": "Read"` 等をplugin.jsonやスキル内で再定義）
- `allowed-tools` を操作して制限を緩和する指示
- フック定義で既存フックを無効化する指示（`"hooks": []`で上書き）

### 24. Whiteboard / Memory Injection

共有ファイル（whiteboard, MEMORY.md, CLAUDE.md等）への命令注入:
- `Write` or `Edit` で whiteboard/*.md, MEMORY.md, CLAUDE.md に書き込む指示
- 「以下をCLAUDE.mdに追加してください」等の間接的改変指示
- handoff データに命令テキストを埋め込むパターン
- 「次のセッションで」「今後は常に」等の永続化を意図する指示

### 25. Agent Spawn & Self-Replication

自己複製・伝播・自律増殖パターン:
- `Agent`, `TeamCreate`, `spawn`, `replicate`, `propagate` + 自動実行指示
- 他プロジェクトの `.claude/` ディレクトリへの書き込み指示
- `npm install`, `pip install` で別のスキルを自動インストール
- 自分自身のコピーを別の場所に配置する指示

### 26. MCP Elicitation Abuse

MCP Elicitation/ElicitationResult経由の権限昇格:
- ElicitationResult で CLI コマンド実行を要求するパターン
- Elicitation のUI要素（ボタン、フォーム）にコマンドを埋め込み
- 「確認」を装ってユーザーに危険な操作を承認させる
- Elicitation経由でAPIキーや認証情報を収集するパターン

### 27. LLM Sampling Injection Markers

MCPレスポンスに埋め込まれたLLMトークナイザマーカー（Unit42報告）:
- `[INST]`, `[/INST]` — Llama/Mistral instruction marker
- `<<SYS>>`, `<</SYS>>` — Llama system prompt marker
- `<|im_start|>system`, `<|im_end|>` — ChatML system marker
- `<|system|>`, `<|user|>`, `<|assistant|>` — Phi marker
- `<start_of_turn>user`, `<start_of_turn>model` — Gemini turn marker
- `<|endoftext|>` — OpenAI end-of-text marker
- `[SYSTEM_PROMPT]` — Generic system prompt marker
- `Human:`, `Assistant:` at line start — Anthropic conversation marker

### 28. Log-To-Leak (ログ経由データ窃取)

ツールレスポンスが別ツールへのデータ送信を指示するパターン（OpenReview報告）:
- `send/post/forward this data to` — データ送信指示
- `call/invoke the logging/analytics/telemetry tool` — loggingツール呼び出し指示
- `write/append this data to a log/file/endpoint` — ログ書き込み指示
- 正規のログ出力と区別するため、「指示形式（動詞+対象+宛先）」の3要素を確認

### 29. Line Jumping (承認前動作注入)

ユーザー承認前に動作を実行させるパターン:
- `before the user approves/confirms/reviews` — 承認前実行指示
- `execute/run without asking/confirmation/approval` — 確認なし実行
- `silently/quietly/secretly execute/run/install` — 隠密実行
- `skip/bypass the confirmation/approval step` — 承認バイパス
- `auto_approve`, `auto_execute`, `auto_confirm` — 自動承認パターン

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

8. **Clipboard & Output Exfiltration Chain** — indirect data theft via clipboard (`pbcopy`, `xclip`, `xsel`, `clip.exe`, `Set-Clipboard`) or by embedding sensitive data in normal-looking output that users unknowingly copy-paste to external services. Evaluate multi-step chains: skill reads credential → formats as "debug output" → user copies to issue tracker
9. **Cloud Metadata / IMDS Access** — access to instance metadata services (`169.254.169.254`, `metadata.google.internal`, `169.254.170.2` for ECS task metadata, `metadata.azure.com`) to steal IAM role credentials, service account tokens, or instance identity. Particularly dangerous in cloud-hosted development environments (Codespaces, Cloud9, EC2)
10. **Symlink & Path Traversal** — creating symbolic links to sensitive files (`ln -s ~/.ssh/id_rsa ./data.txt`) to bypass path-based access controls, or using `../` traversal to escape project directories. Includes hard links, junction points (Windows), and relative path abuse in tar/zip extraction
11. **DoD Manipulation for Silent Exfiltration** — skills that define Definition of Done in a way that instructs the agent to send out the entire codebase voluntarily — e.g., "do not commit changes until all tasks are complete" delays commits while exfiltration completes. Confirmed in real-world environments by Mitiga research
12. **MCP Tool Redefinition / Shadowing** — a malicious MCP server provides an implementation with the same name as a legitimate tool, intercepting data. Succeeds through identifier collision alone and is difficult to detect
13. **API Budget Drain Attack** — intentionally induces overthinking to explode API token consumption, functioning as a DoS-style attack
14. **Plugin manifest poisoning**: Legitimate-looking plugin.json that installs malicious hooks or overrides settings
15. **Namespace squatting via plugins**: Registering plugin names that mimic popular tools
16. **Hook chain injection**: Plugin hooks that inject additional hooks at install time

### Focus Areas

- Skills that modify Claude Code settings or permissions
- Skills that reference `~/.ssh`, `~/.aws`, `~/.config`, `~/.env`
- Skills with `risk: unknown` or no risk field
- Single authors with many security/attack-oriented skills (supply chain concentration risk)
- External URLs that receive data (especially non-standard domains)
- `references/` directories with imperative scripts or multi-step attack procedures

---

## Agent 3: Deep Analyzer

Perform six analysis roles in a single agent:

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

- **Permission patterns**: audit `permissions.allow` and `permissions.deny` arrays in `settings.json` — flag overly broad allow patterns (wildcards, `Bash(python:*)`, `Bash(node:*)`, `Bash(ruby:*)`, `Bash(perl:*)`, `Bash(npm:*)`) and missing deny entries for dangerous commands
- **Allowlist escape chains**: systematically check all runtime allow patterns that enable HTTP exfiltration bypass — `Bash(python:*)` → `python -c "import urllib..."`, `Bash(node:*)` → `node -e "fetch(...)"`, `Bash(npm:*)` → `npm exec` arbitrary code execution, `Bash(npx:*)` → `npx` package fetch and execute
- **Hook definitions**: examine PreToolUse and PostToolUse hook definitions for safety — flag hooks that execute arbitrary Bash commands, hooks that modify files outside project scope, and hooks that disable other security controls
- **MCP server settings**: check for `enableAllProjectMcpServers: true` which auto-trusts all project-level MCP servers without user confirmation
- **Hook command safety**: analyze Bash commands within hook definitions for dangerous patterns (data exfiltration, privilege escalation, credential access) — hooks run automatically and bypass normal approval flows
- **API endpoint integrity**: check for `ANTHROPIC_BASE_URL` or proxy environment variable overrides in hook commands or skill instructions that redirect API traffic

#### allowed-tools Audit

- Check all SKILL.md files for `allowed-tools` frontmatter
- **Missing allowed-tools** on skills that use Bash or Write → **High risk** (unrestricted tool access)
- **Missing allowed-tools** on other skills → **Medium risk** (recommend explicit declaration)
- Verify declared allowed-tools match actual tool usage in skill instructions
- Flag skills that request `Bash` + `Write` + `Edit` together (maximum attack surface)

### Role E: Skill Interconnection Risk

Analyze how skills could be combined to create attack chains:

- Map skills that provide reconnaissance capabilities (port scanning, service enumeration, OSINT)
- Map skills that provide exploitation capabilities (vulnerability exploitation, payload generation)
- Map skills that provide persistence capabilities (backdoor creation, credential harvesting)
- Flag any recon → exploit → persist chains that could be executed in a single session
- Check if high-risk skills properly require user confirmation at each escalation step

### Role F: Temporal Attack Analysis

Detect time-delayed or conditional attack patterns that evade single-scan detection:

- **Conditional triggers**: code that checks for specific conditions before executing malicious payloads — `if os.path.exists(".claude/settings.json")` (only activates in Claude Code environment), date-based triggers (`datetime.now() > datetime(2026, ...)`) , environment detection (`if "CODESPACE" in os.environ`)
- **Progressive escalation over sessions**: first invocation is benign (builds trust), subsequent invocations gradually escalate — writing a config file on first run, reading it on second run to determine "returning user" and enabling dangerous features
- **Delayed payload delivery**: instructions that reference external URLs for "updates" or "latest version" — the URL content can change after initial review to deliver malicious payloads
- **State file manipulation**: skills that create dot-files (`.skill-cache`, `.skill-config`) in project directories and change behavior based on their contents — benign on first run, escalating on subsequent runs

### Role G: Auto Mode Risk Analysis

Analyze risks specific to Claude Code Auto Mode (research preview as of 2026-03):

- **Auto Mode-assumed operation instructions**: descriptions stating "no confirmation required" or "this will be automatically approved", assuming Auto Mode will execute dangerous operations without human review
- **Attacks that only succeed in Auto Mode**: patterns designed to bypass human approval — evaluate whether the attack would fail if a human were in the loop
- **Exploitation of areas Anthropic itself acknowledges as incompletely protected**: deliberate abuse of known limitations, such as indirect prompt injection via external data sources, trust boundary confusion between skill instructions and MCP responses, and operations that are individually safe but dangerous in sequence

---

## Synthesis (Main Agent)

After all 3 agents report, classify every finding:

| Verdict | Criteria | Action |
|---------|----------|--------|
| **DELETE** | Sends credentials to unofficial external servers / auto-enables bypassPermissions / confirmed prompt injection | Remove immediately |
| **ACTION REQUIRED** | shell=True with user input / plaintext credential storage / recursive .env search in parent dirs / piped shell execution / backdoor persistence instructions without risk:high / XOR/dynamic encoding obfuscation / agent-to-agent auto-install instructions | Fix or establish operational rules |
| **CAUTION** | External API dependency (API key required) / educational attack patterns / cognitive manipulation false positives / high-risk skills properly marked with risk:high / Auto Mode-assumed operation instructions (harmless in non-Auto Mode environments) | Note for awareness |
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

## Runtime Defense: MCP Response Inspector Hook

In addition to static analysis, this project includes a **runtime PostToolUse hook** that inspects MCP tool responses in real-time.

See [`hooks/README.md`](hooks/README.md) for installation and details.

**Why runtime matters**: Static analysis catches malicious patterns in skill files *before* execution. But MCP server responses arrive *at runtime* — the same structural vulnerability as cloned OSS backdoors where AI follows existing patterns including malicious ones. Without runtime inspection, injected instructions in MCP responses are treated as trusted data.

| Layer | Tool | When |
|-------|------|------|
| Static | `skill-scanner` / Skill mode agents | Before execution (skill audit) |
| Static | Community threat intel | Before execution (latest attack patterns) |
| Runtime | `mcp-response-inspector.mjs` hook | During execution (MCP response inspection) |
| Runtime | `validate-bash.sh` hook | During execution (dangerous command prevention) |
| Runtime | `ghost-file-detector.sh` hook | During execution (AI anti-pattern detection) |
| Policy | FIDES trust levels | Always (data trust classification) |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

*Maintained by [@aliksir](https://github.com/aliksir) — Issues and PRs welcome.*
