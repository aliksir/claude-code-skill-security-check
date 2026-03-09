#!/bin/bash
# validate-bash.sh - 危険コマンドのみブロック（自走モード用）
input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name // ""')

if [[ "$tool_name" != "Bash" ]]; then
  exit 0
fi

command=$(echo "$input" | jq -r '.tool_input.command // ""')

# 引用符内のリテラル文字列を除去した版（誤検知防止用）
# python -c "...git push --force..."、gh pr create --body "..." 等で
# 文字列リテラル内のキーワードを危険コマンドと誤認するのを防ぐ。
# Tier 5-7（インラインコード検出）はあえて引用符内を検査するので $command を使う。
command_unquoted=$(echo "$command" | sed "s/'[^']*'//g; s/\"[^\"]*\"//g")

deny() {
  local reason="$1"
  local fix="${2:-}"
  local full_reason="$reason"
  if [[ -n "$fix" ]]; then
    full_reason="$reason → 代替: $fix"
  fi
  jq -n --arg reason "$full_reason" '{
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": $reason
    }
  }'
  exit 0
}

# === Tier 1: 絶対禁止（システム破壊） ===
# ルート直下 "/" または "/etc", "/usr", "/bin", "/lib", "/sys", "/boot", "/dev", "/proc" へのrm -rf をブロック
# "/tmp", "/home", "/work" 等のユーザー作業領域は通す
if echo "$command_unquoted" | grep -qiE '\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\s+(/\s*$|/(etc|usr|bin|sbin|lib|lib64|boot|sys|dev|proc|run)\b)'; then
  deny "rm -rf / 系のシステム破壊コマンドは禁止です" "対象ファイルを個別にrm、または_deleted/に退避"
fi

if echo "$command_unquoted" | grep -qiE '\bformat\s+[a-zA-Z]:'; then
  deny "ドライブフォーマットは禁止です"
fi

if echo "$command_unquoted" | grep -qiE '\bdel\s+/[fFsS].*\\'; then
  deny "del /f 系の一括削除は禁止です"
fi

# === Tier 2: 確認必須（git push系） ===
if echo "$command_unquoted" | grep -qE '\bgit\s+push\b.*--force'; then
  deny "git push --force は禁止です。総司令に確認してください" "git push（通常push）または git push --force-with-lease"
fi

if echo "$command_unquoted" | grep -qE '\bgit\s+push\b.*\b(main|master)\b'; then
  deny "main/master への直接 push は禁止です。総司令に確認してください" "featureブランチにpushしてPRを作成"
fi

if echo "$command_unquoted" | grep -qE '\bgit\s+reset\s+--hard'; then
  deny "git reset --hard は禁止です。総司令に確認してください" "git stash または git checkout -- <file>"
fi

# === Tier 3: 注意（git add -A 防止） ===
if echo "$command_unquoted" | grep -qE '\bgit\s+add\s+(-A|--all|\.\s*$)'; then
  deny "git add -A/--all/. は禁止です" "git add file1.py file2.py のように個別指定"
fi

# === Tier 4: パイプ経由スクリプト実行 ===
if echo "$command_unquoted" | grep -qE '\bcurl\b.*\|\s*(bash|sh|zsh)\b'; then
  deny "curl | bash パターンは禁止です" "curl -o script.sh URL && cat script.sh && bash script.sh"
fi

if echo "$command_unquoted" | grep -qE '\bwget\b.*\|\s*(bash|sh|zsh)\b'; then
  deny "wget | bash パターンは禁止です" "wget -O script.sh URL && cat script.sh && bash script.sh"
fi

# === Tier 5: HTTP exfiltration（curl denyバイパス防止） ===
# python -c / python3 -c でHTTPモジュールを直接呼ぶインラインコードをブロック
# 通常の python script.py や python -m pytest は通す
if echo "$command" | grep -qiE '\bpython3?\s+-(c|.*c)\s.*\b(urllib|requests|http\.client|httpx|socket\.connect)\b'; then
  deny "Python inline コードでのHTTP通信は禁止です（exfiltration対策）。スクリプトファイル経由で実行してください"
fi

# node -e でHTTP通信するインラインコードをブロック
# 通常の node script.js は通す
if echo "$command" | grep -qiE '\bnode\s+-(e|.*e)\s.*\b(fetch|http\.get|https\.get|require.*http|XMLHttpRequest|axios)\b'; then
  deny "Node inline コードでのHTTP通信は禁止です（exfiltration対策）。スクリプトファイル経由で実行してください"
fi

# === Tier 6: 機密ファイルの直接読み取り防止 ===
# SSH秘密鍵・設定（\bはドット前で効かないため、パス区切り前提で検知）
if echo "$command" | grep -qiE '\b(cat|head|tail|less|more|cp|scp|base64|xxd)\b.*[/\\]\.ssh/(id_|config|known_hosts|authorized_keys|[a-z]+_key)'; then
  deny "SSH鍵/設定の直接読み取りは禁止です。総司令に確認してください"
fi

# AWS認証情報
if echo "$command" | grep -qiE '\b(cat|head|tail|less|more|cp|base64)\b.*[/\\]\.aws/(credentials|config)'; then
  deny "AWS認証情報の直接読み取りは禁止です。総司令に確認してください"
fi

# GCP認証情報
if echo "$command" | grep -qiE '\b(cat|head|tail|less|more|cp|base64)\b.*(application_default_credentials\.json|[/\\]gcloud/credentials)'; then
  deny "GCP認証情報の直接読み取りは禁止です。総司令に確認してください"
fi

# Azure認証情報
if echo "$command" | grep -qiE '\b(cat|head|tail|less|more|cp|base64)\b.*[/\\]\.azure/(accessTokens|azureProfile)'; then
  deny "Azure認証情報の直接読み取りは禁止です。総司令に確認してください"
fi

# === Tier 7: 環境変数からの秘密情報漏洩 ===
# env/printenv の出力をパイプで外部送信するパターン
if echo "$command" | grep -qiE '\b(env|printenv|set)\b.*\|\s*(curl|wget|python3?|node|nc|ncat)\b'; then
  deny "環境変数の外部送信は禁止です"
fi

# === Tier 7.5: セキュリティスキャン結果の外部送信防止 ===
if echo "$command" | grep -qiE '\b(curl|wget)\b.*(-F|--data-binary|--upload-file|-d\s|--data\s).*\b(report|scan-result|gitleaks|trivy|semgrep|bandit|osv-scanner|sarif|\.json)\b'; then
  deny "セキュリティスキャン結果の外部送信は禁止です"
fi

# === Tier 8: AWS/IaC 破壊コマンド防止 ===
# AWS CLI: リソース削除系（delete-*, terminate-*, deregister-*, remove-tags は通す）
if echo "$command_unquoted" | grep -qiE '\baws\s+\S+\s+(delete-|terminate-|remove-|destroy-|deregister-)\S+'; then
  # remove-tags は安全なので除外
  if ! echo "$command_unquoted" | grep -qiE '\baws\s+\S+\s+remove-tags\b'; then
    deny "AWS リソース削除コマンドは禁止です。総司令に確認してください" "aws <service> describe-* / list-* / get-* で確認のみ"
  fi
fi

# AWS CLI: IAM権限操作（権限昇格防止）
if echo "$command_unquoted" | grep -qiE '\baws\s+iam\s+(create-user|create-access-key|attach-.*-policy|put-user-policy|put-role-policy|create-login-profile|update-assume-role-policy)\b'; then
  deny "AWS IAM権限操作は禁止です。総司令に確認してください" "aws iam list-* / get-* で参照のみ"
fi

# AWS CLI: アカウント全体に影響する操作
if echo "$command_unquoted" | grep -qiE '\baws\s+(organizations|account)\s+(leave-organization|close-account|delete-organization)\b'; then
  deny "AWSアカウント/Organization操作は禁止です。総司令に確認してください"
fi

# Terraform: 破壊系コマンド
if echo "$command_unquoted" | grep -qiE '\bterraform\s+(destroy|apply\s+-auto-approve)\b'; then
  deny "terraform destroy / apply -auto-approve は禁止です。総司令に確認してください" "terraform plan で確認、apply は plan.tfplan 指定"
fi

# Terraform: plan なしの apply（-auto-approve なしでも確認必須）
if echo "$command_unquoted" | grep -qiE '\bterraform\s+apply\b' && ! echo "$command_unquoted" | grep -qiE '\bterraform\s+apply\s+.*\.tfplan\b'; then
  deny "terraform apply はplanファイル指定が必須です。総司令に確認してください" "terraform plan -out=plan.tfplan && terraform apply plan.tfplan"
fi

# CDK: 破壊系コマンド
if echo "$command_unquoted" | grep -qiE '\bcdk\s+destroy\b'; then
  deny "cdk destroy は禁止です。総司令に確認してください" "cdk diff でスタック差分を確認"
fi

# Pulumi: 破壊系コマンド
if echo "$command_unquoted" | grep -qiE '\bpulumi\s+(destroy|up\s+--yes)\b'; then
  deny "pulumi destroy / up --yes は禁止です。総司令に確認してください" "pulumi preview で確認"
fi

# === Tier 9: リバースシェル検知 ===
if echo "$command_unquoted" | grep -qiE '\b(bash|sh|zsh)\s+(-i\s+)?>(\/dev\/tcp|&\/dev\/tcp)'; then
  deny "リバースシェルは禁止です"
fi

if echo "$command_unquoted" | grep -qiE '\bnc\b.*\s-e\s.*(bash|sh|zsh)'; then
  deny "netcat リバースシェルは禁止です"
fi

exit 0
