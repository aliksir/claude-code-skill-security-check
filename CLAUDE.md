# claude-code-skill-security-check

Claude Code コミュニティスキルのセキュリティ監査ツール。スキルモード（Claude Code 内蔵エージェント 3 並列）と CLI モード（skill-scanner Python パッケージ）の 2 形態で提供。

## 技術スタック

- Node.js >= 18（ESM）— インストーラー（install.js）
- Python — CLI ツール `skill-scanner`（別パッケージ）
- Semgrep — カスタムルール 7 件（SSRF / SQL インジェクション / 弱暗号 / 安全でないデシリアライズ / Angular DOM XSS / パストラバーサル / IDOR）

## セットアップ

npm 経由（推奨）:

```bash
npx claude-code-skill-security-check
```

CLI ツール（skill-scanner）を使う場合:

```bash
pip install skill-scanner
```

## ビルド

該当なし

## テスト

該当なし（package.json に test スクリプト未定義）

## 開発規約

- スキルモードは外部ツールのインストールを要求しない。Claude Code built-in ツールのみ使用する
- スキルモードはファイルを読み取るのみで、変更・削除は行わない
- 検出パターンの誤検知は許容する（偽陰性より偽陽性を優先する）
- ランタイムフックはエラー時に安全側（通過）で動作する
- セキュリティ教育目的のコンテンツ（pentest skills 等）は文脈を考慮して判定する
