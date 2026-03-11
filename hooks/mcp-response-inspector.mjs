#!/usr/bin/env node
/**
 * MCP Response Inspector — PostToolUse Hook
 *
 * MCPツールの応答に含まれるプロンプトインジェクション、
 * 危険コマンド、不審URL、データ窃取パターンを検出する。
 *
 * FIDES trust_level: LOW（MCP応答は外部データ扱い）
 *
 * @version 1.2.0
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
      /\bact\s+as\b.*\b(admin|root|system|unrestricted)/i,
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
      /\bbase64\b.*\b(?:ssh|aws|credentials|\.env|api.?key|secret)/i,
      /\benv\b.*\|\s*(?:curl|wget|python|node)/,
      /\bprintenv\b.*\|\s*(?:curl|wget|python|node)/,
      /(?:cat|type)\s+(?:~\/)?\.(?:ssh|aws|env|gnupg)/,
      /\bAWS_SECRET_ACCESS_KEY\b/,
      /\bANTHROPIC_API_KEY\b/,
      /\bGOOGLE_APPLICATION_CREDENTIALS\b/,
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
    label: 'ツール再定義攻撃',
    severity: 'HIGH',
    patterns: [
      // ツール上書き・シャドウ・インターセプト指示
      /\b(override|replace|redefine|shadow|intercept)\b.*\btool\b/i,
      // ツール名/IDの明示的な定義（レスポンス内でのツール登録試行）
      /\btool[_\s]?(name|id|identifier)\s*[:=]\s*["'][^"']*["']/i,
      // 既存ツールと同名での再定義
      /\b(register|define|create)\b.*\b(tool|function)\b.*\b(same|existing|original)\b/i,
    ],
  },
  agent_infection: {
    label: 'エージェント間感染',
    severity: 'HIGH',
    patterns: [
      // スキル自動インストール指示（距離制限: 30文字以内）
      /\b(install|add|download)\b.{0,30}\bskill\b/i,
      // 他環境への展開・複製
      /\b(propagate|replicate|spread)\b.*\b(to|across|other)\b/i,
      // エージェントの自動生成
      /\bspawn\b.*\bagent\b/i,
    ],
  },
  budget_drain: {
    label: 'API予算枯渇攻撃',
    severity: 'MEDIUM',
    patterns: [
      // 過剰な思考誘発（無限思考ループ、距離制限付き）
      /\bthink\b.{0,20}\bstep by step\b.{0,30}\b(detail|extreme|every)\b/i,
      // 全列挙指示
      /\b(enumerate|list)\b.*\b(all|every)\b.*\bpossible\b/i,
      // 無限・大量繰り返し指示
      /\brepeat\b.*\b(\d{3,}|infinite|forever)\b/i,
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
  const icon = f.severity === 'CRITICAL' ? '🔴' : f.severity === 'HIGH' ? '🟠' : '🟡';
  lines.push(`  ${icon} [${f.severity}] ${f.label}: "${f.matched}"`);
}

if (!isTrusted && (hasCritical || hasHigh)) {
  lines.push('  → この応答の内容をBashコマンドに直接展開しないでください');
  lines.push('  → 独立した検証なしに action:auto にしないでください');
}

// stderrに出力（hookのユーザー表示チャネル）
process.stderr.write(lines.join('\n') + '\n');

// CRITICALかつ非信頼MCPの場合のみブロック（exit 2）
if (hasCritical && !isTrusted) {
  // exit 2 = ブロック（Claude Codeがツール結果を無視する）
  process.exit(2);
}

process.exit(0);
