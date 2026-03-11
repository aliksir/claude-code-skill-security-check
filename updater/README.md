# Update Checker

`check-update.sh` は Skill Security Check の新バージョンをチェックするスクリプトです。

- **デフォルトOFF** — インストールするだけでは動きません。明示的にONにする必要があります
- **通知のみ** — 自動更新はしません。新バージョンがあれば表示するだけです
- **24時間キャッシュ** — 一度チェックしたら24時間は再チェックしません

---

## 手動チェック

いつでも手動でチェックできます。

```bash
# 通常（24時間キャッシュあり）
bash updater/check-update.sh

# キャッシュを無視して即時チェック
bash updater/check-update.sh --force
```

新バージョンがある場合、以下のような通知がstderrに表示されます。

```
🔔 Skill Security Check: 新バージョン v2.3.0 が利用可能です（現在: v2.2.0）
   → https://github.com/aliksir/claude-code-skill-security-check/blob/master/CHANGELOG.md
```

バージョンが最新の場合は何も表示されません。

---

## 自動チェックON（SessionStartフック）

Claude Code のセッション開始時にバックグラウンドで自動チェックするには、
`settings.json` にフックを追加します。

### 設定手順

1. `~/.claude/settings.json` を開く（存在しない場合は新規作成）
2. 以下の JSON を追加する

```json
{
  "hooks": {
    "SessionStart": [
      {
        "type": "command",
        "command": "bash ~/.claude/skill-security-check/updater/check-update.sh &",
        "timeout": 10000
      }
    ]
  }
}
```

> **パスについて**: `~/.claude/skill-security-check/` はリポジトリをクローンした場所に合わせて変更してください。

### 既存のフックがある場合

`SessionStart` がすでに配列で定義されている場合は、配列に追記します。

```json
{
  "hooks": {
    "SessionStart": [
      {
        "type": "command",
        "command": "既存のコマンド"
      },
      {
        "type": "command",
        "command": "bash ~/.claude/skill-security-check/updater/check-update.sh &",
        "timeout": 10000
      }
    ]
  }
}
```

---

## 自動チェックOFF

`settings.json` の `SessionStart` セクションから、追加したフックのエントリを削除するだけです。

---

## キャッシュのリセット

```bash
rm -f ~/.claude/.skill-security-check-update-cache
```

次回実行時に即時チェックが走ります。

---

## 動作環境

- Linux / macOS / Windows (Git Bash / MSYS2)
- `curl` が必要です（インストールされていない場合はサイレントにスキップ）
- `bash` 3.2 以上
