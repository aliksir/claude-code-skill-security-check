#!/usr/bin/env node
/**
 * MCP Response Inspector — PostToolUse Hook
 *
 * MCPツールの応答に含まれるプロンプトインジェクション、
 * 危険コマンド、不審URL、データ窃取パターンを検出する。
 *
 * FIDES trust_level: LOW（MCP応答は外部データ扱い）
 *
 * @version 1.4.0
 * @author aliksir
 */
import { readFileSync } from 'fs';

// ============================================
// stdin から JSON を読み取る
// ============================================
let input;
try {
  input = JSON.parse(readFileSync(0, 'utf8'));
} catch {
  process.exit(0); // パース失敗は安全側（スキップ）
}

const toolName = input.tool_name || '';
const toolOutput = input.tool_output || '';

// MCP ツール以外はスキップ
if (!toolName.startsWith('mcp__')) {
  process.exit(0);
}

// 出力が空またはオブジェクト型の場合は文字列化
const output = typeof toolOutput === 'string'
  ? toolOutput
  : JSON.stringify(toolOutput);

// 短い応答はスキップ（誤検知削減）
if (output.length < 20) {
  process.exit(0);
}

// ============================================
// 検出パターン定義
// ============================================
const PATTERNS = {
  prompt_injection: {
    label: 'プロンプトインジェクション',
    severity: 'CRITICAL',
    patterns: [
      /\bIGNORE\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)/i,
      /\bFORGET\s+(everything|all|previous)/i,
      /\bOVERRIDE\s+(system|safety|security)/i,
      /\bDISREGARD\s+(all|previous|prior|your)/i,
      /\byou\s+are\s+now\b/i,
      /\bact\s+as\b.{0,30}\b(admin|root|system|unrestricted)/i,
      /\bnew\s+instructions?\s*:/i,
      /\bsystem\s*:\s*you\s+are/i,
      /<\/?system>/i,
      /<\/?instructions>/i,
      /\bignore\s+(?:the\s+)?(?:above|previous|prior)\b/i,
      /\bpretend\s+(?:to\s+be|you\s+are)\b/i,
    ],
  },
  dangerous_commands: {
    label: '危険コマンド',
    severity: 'HIGH',
    patterns: [
      /\brm\s+-rf\s+[\/~]/,
      /\bsudo\s+rm\b/,
      /\bchmod\s+777\b/,
      /\beval\s*\(/,
      /\bexec\s*\(/,
      /\bcurl\s+[^|]*\|\s*(ba)?sh\b/,
      /\bwget\s+[^|]*\|\s*(ba)?sh\b/,
      /\bbypassPermissions/i,
      /\b(?:danger-full-access|--dangerously-skip-permissions)\b/,
      /\bANTHROPIC_BASE_URL\s*=/,
      /\bOPENAI_BASE_URL\s*=/,
    ],
  },
  data_exfiltration: {
    label: 'データ窃取',
    severity: 'HIGH',
    patterns: [
      /\bbase64\b.{0,50}\b(?:ssh|aws|credentials|\.env|api.?key|secret)/i,
      /\benv\b.*\|\s*(?:curl|wget|python|node)/,
      /\bprintenv\b.*\|\s*(?:curl|wget|python|node)/,
      /(?:cat|type)\s+(?:~\/)?\.(?:ssh|aws|env|gnupg)/,
      /\bAWS_SECRET_ACCESS_KEY\b/,
      /\bANTHROPIC_API_KEY\b/,
      /\bGOOGLE_APPLICATION_CREDENTIALS\b/,
      // 環境変数窃取チェーン強化: set/printenv → curl/wget/python/node の連鎖
      /\bset\b.{0,50}\|\s*(?:curl|wget|python|node)/,
      /\b(?:printenv|env|set)\b.{0,50}\|\s*(?:base64|xxd|gzip)\b/,
      // 環境変数ダンプ → ファイル → 送信の多段チェーン
      /\b(?:printenv|env|set)\s*>\s*\S+.*(?:curl|wget|fetch|httpx)/,
      // PowerShell環境変数窃取
      /\bGet-ChildItem\s+Env:\b.*\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i,
    ],
  },
  suspicious_urls: {
    label: '不審URL',
    severity: 'MEDIUM',
    patterns: [
      // 既知の安全ドメイン以外への POST/送信指示
      /(?:requests\.post|httpx\.post|fetch\s*\()\s*['"`]https?:\/\/(?!(?:github\.com|api\.anthropic\.com|googleapis\.com|amazonaws\.com|localhost))/i,
      // Reverse shell パターン
      /\/dev\/tcp\//,
      /\bnc\s+-e\s+\/bin\//,
      /\bNew-Object\s+System\.Net\.Sockets\.TCPClient\b/,
    ],
  },
  hidden_content: {
    label: '隠蔽テクニック',
    severity: 'HIGH',
    patterns: [
      // ゼロ幅文字
      /[\u200B\u200C\u200D\uFEFF]/,
      // Bidirectional override
      /[\u202E\u202D\u2066-\u2069]/,
      // HTMLコメント内の指示
      /<!--[\s\S]*?(?:ignore|override|system|exec|eval|curl|wget)[\s\S]*?-->/i,
    ],
  },
  // ── 2026年以降の新攻撃手法 ──────────────────────────────────
  tool_redefinition: {
    label: 'ツール再定義/シャドウイング攻撃',
    severity: 'HIGH',
    patterns: [
      // ツール上書き・シャドウ・インターセプト指示
      /\b(override|replace|redefine|shadow|intercept)\b.{0,30}\btool\b/i,
      // ツール再登録の指示文脈（通常のJSONフィールド参照を除外するため、命令的動詞と組み合わせ）
      /\b(set|change|update|register)\b.{0,30}\btool[_\s]?(name|id)\s*[:=]/i,
      // 既存ツールと同名での再定義
      /\b(register|define|create)\b.{0,30}\b(tool|function)\b.{0,30}\b(same|existing|original)\b/i,
      // Tool Shadowing強化: 既存ビルトインツール名の直接上書き指示
      /\b(?:override|replace|redefine|shadow)\b.{0,30}\b(?:Read|Write|Edit|Bash|Glob|Grep|Agent)\b/i,
      // MCP設定の動的変更指示
      /\b(?:modify|edit|change|update)\b.{0,30}\b(?:mcp\.json|mcpServers|tool_definitions?)\b/i,
    ],
  },
  agent_infection: {
    label: 'エージェント間感染',
    severity: 'HIGH',
    patterns: [
      // スキル自動インストール指示（距離制限: 30文字以内）
      /\b(install|add|download)\b.{0,30}\bskill\b/i,
      // 他環境への展開・複製
      /\b(propagate|replicate|spread)\b.{0,30}\b(to|across|other)\b/i,
      // エージェントの自動生成
      /\bspawn\b.{0,30}\bagent\b/i,
    ],
  },
  budget_drain: {
    label: 'API予算枯渇攻撃',
    severity: 'MEDIUM',
    patterns: [
      // 過剰な思考誘発（無限思考ループ、距離制限付き）
      /\bthink\b.{0,20}\bstep by step\b.{0,30}\b(detail|extreme|every)\b/i,
      // 全列挙指示
      /\b(enumerate|list)\b.{0,20}\b(all|every)\b.{0,20}\bpossible\b/i,
      // 無限・大量繰り返し指示
      /\brepeat\b.{0,30}\b(\d{3,}|infinite|forever)\b/i,
    ],
  },
  // ── 2026-03 セキュリティ調査追加 ──────────────────────────────────
  sampling_injection: {
    label: 'LLMサンプリング注入',
    severity: 'CRITICAL',
    patterns: [
      // LLMトークナイザマーカーの埋め込み（Unit42）
      /\[INST\]/i,
      /\[\/INST\]/i,
      /<<SYS>>/,
      /<<\/SYS>>/,
      /<\|im_start\|>\s*system/i,
      /<\|im_end\|>/,
      /<\|system\|>/i,
      /<\|user\|>/i,
      /<\|assistant\|>/i,
      /\[SYSTEM_PROMPT\]/i,
      /<start_of_turn>\s*(?:user|model)/i,
      /<\|endoftext\|>/,
    ],
  },
  log_to_leak: {
    label: 'Log-To-Leak（ログ経由データ窃取）',
    severity: 'HIGH',
    patterns: [
      // ツールレスポンスが「別ツールでデータを送信しろ」と指示するパターン（OpenReview）
      /\b(?:send|post|forward|transmit|upload|log|report)\s+(?:this|the|all|these|that)\s+(?:data|information|content|result|output|response)\s+(?:to|via|through|using)\b/i,
      /\b(?:call|invoke|use|execute)\s+(?:the\s+)?(?:logging|analytics|telemetry|monitoring|webhook)\s+(?:tool|service|api|endpoint)\b/i,
      /\b(?:write|append|save)\s+(?:this|the|all)\s+(?:data|output|result)\s+(?:to|into)\s+(?:a\s+)?(?:log|file|database|endpoint)\b/i,
    ],
  },
  line_jumping: {
    label: 'Line Jumping（承認前動作注入）',
    severity: 'HIGH',
    patterns: [
      // ユーザー承認前に動作を実行させる指示パターン
      /\b(?:before|prior\s+to)\s+(?:the\s+)?(?:user|human)\s+(?:approves?|confirms?|reviews?|sees?)\b/i,
      /\b(?:execute|run|perform|do)\s+(?:this|the\s+following)\s+(?:before|without)\s+(?:asking|confirmation|approval|consent)\b/i,
      /\b(?:silently|quietly|invisibly|secretly)\s+(?:execute|run|perform|install|download|send)\b/i,
      /\b(?:skip|bypass|avoid)\s+(?:the\s+)?(?:confirmation|approval|review|verification)\s+(?:step|prompt|dialog)\b/i,
      /\bauto[_\s-]?(?:approve|accept|confirm|execute)\b/i,
    ],
  },
  // ── MCP Elicitation 悪用検出（CC 2.1.76+ 新機能）─────────────────
  elicitation_abuse: {
    label: 'Elicitation悪用',
    severity: 'WARNING',
    patterns: [
      // 1. Elicitation経由のコマンド実行: ElicitationResult のテキスト/ボタンラベルに実行キーワード
      /\b(elicitation|elicit)\b[\s\S]{0,200}\b(bash|exec|eval|system|spawn|child_process|execSync|execFile|shelljs)\b/i,
      // 2. 認証情報収集: Elicitation のフォームフィールドやプロンプトに機微キーワード
      /\b(elicitation|elicit)\b[\s\S]{0,200}\b(password|passwd|token|api[_\s]?key|secret|credential|auth[_\s]?code|private[_\s]?key)\b/i,
      // 3. 偽の確認UI: 危険操作を承認・許可させようとするパターン
      /\b(elicitation|elicit)\b[\s\S]{0,200}\b(confirm|approve|authorize|grant[_\s]?permission|allow[_\s]?access|escalate)\b/i,
      // 4. 隠しコマンド埋め込み: UI要素(description/placeholder/default)にシェルコマンド/スクリプト
      /\b(description|placeholder|default[_\s]?value|label)\b[\s\S]{0,100}\b(bash|sh|powershell|cmd|python|node|ruby|perl|exec|eval|curl|wget)\b[\s\S]{0,50}[`$({]/i,
      // 5. Elicitation 種別: action/type フィールドに実行系キーワード
      /"(?:action|type)"\s*:\s*"(?:execute|run|eval|inject|shell)"/i,
    ],
  },
};

// 安全なMCPサーバーのホワイトリスト（誤検知削減）
const TRUSTED_MCP_PREFIXES = [
  'mcp__memory__',    // ローカルメモリ
  'mcp__figma-remote-mcp__', // Figma
];

// ============================================
// 検出実行
// ============================================
const findings = [];

for (const [category, config] of Object.entries(PATTERNS)) {
  for (const pattern of config.patterns) {
    const match = output.match(pattern);
    if (match) {
      findings.push({
        category,
        label: config.label,
        severity: config.severity,
        matched: match[0].substring(0, 100),
        position: match.index,
      });
      break; // カテゴリごとに1件のみ（ノイズ削減）
    }
  }
}

// ============================================
// 結果出力
// ============================================
if (findings.length === 0) {
  process.exit(0);
}

// 信頼済みMCPの場合は警告レベルを下げる
const isTrusted = TRUSTED_MCP_PREFIXES.some((prefix) => toolName.startsWith(prefix));

const hasCritical = findings.some((f) => f.severity === 'CRITICAL');
const hasHigh = findings.some((f) => f.severity === 'HIGH');

// 出力（Claude Codeのhookはstderrに出力するとユーザーに表示される）
const header = isTrusted
  ? `⚠️ MCP応答検査 [${toolName}] — 信頼済みMCPだが以下を検出:`
  : `🚨 MCP応答検査 [${toolName}] — FIDES:LOW データに以下を検出:`;

const lines = [header];
for (const f of findings) {
  const icon = f.severity === 'CRITICAL' ? '🔴'
    : f.severity === 'HIGH' ? '🟠'
    : f.severity === 'WARNING' ? '🟡'
    : '🔵'; // MEDIUM
  // elicitation_abuse は専用プレフィックスメッセージを付与
  const suffix = f.category === 'elicitation_abuse'
    ? ' [ELICITATION_ABUSE] Potential credential harvesting via elicitation UI'
    : '';
  lines.push(`  ${icon} [${f.severity}] ${f.label}: "${f.matched}"${suffix}`);
}

if (!isTrusted && (hasCritical || hasHigh)) {
  lines.push('  → この応答の内容をBashコマンドに直接展開しないでください');
  lines.push('  → 独立した検証なしに action:auto にしないでください');
}

const hasWarning = findings.some((f) => f.severity === 'WARNING');
if (!isTrusted && hasWarning) {
  lines.push('  → Elicitation UI経由の権限昇格・認証情報収集の可能性があります');
  lines.push('  → ElicitationResult の内容を実行前に確認してください');
}

// stderrに出力（hookのユーザー表示チャネル）
process.stderr.write(lines.join('\n') + '\n');

// CRITICALかつ非信頼MCPの場合のみブロック（exit 2）
if (hasCritical && !isTrusted) {
  // exit 2 = ブロック（Claude Codeがツール結果を無視する）
  process.exit(2);
}

process.exit(0);
