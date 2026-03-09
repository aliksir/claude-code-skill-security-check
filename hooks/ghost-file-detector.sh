#!/bin/bash
# ghost-file-detector.sh - ゴーストファイル（類似名の新規ファイル）検出
# AI生成コードのアンチパターン: 既存ファイルを修正せず類似名で新規作成する
# PostToolUse で Write ツールを監視し、類似ファイル発見時に警告

input=$(cat)
tool_name=$(echo "$input" | jq -r '.tool_name // ""')

# Write ツールのみ対象
if [[ "$tool_name" != "Write" ]]; then
  exit 0
fi

file_path=$(echo "$input" | jq -r '.tool_input.file_path // ""')
if [[ -z "$file_path" ]]; then
  exit 0
fi

# ディレクトリとファイル名を分解
dir=$(dirname "$file_path")
basename_full=$(basename "$file_path")
extension="${basename_full##*.}"
basename_noext="${basename_full%.*}"

# 拡張子がない場合
if [[ "$basename_full" == "$extension" ]]; then
  extension=""
fi

# 末尾の数字を除去 (utils2 -> utils, helper3 -> helper)
base_stripped=$(echo "$basename_noext" | sed -E 's/[0-9]+$//')
# 末尾の _new, _copy, _backup, _old を除去
base_stripped=$(echo "$base_stripped" | sed -E 's/_(new|copy|backup|old|tmp|v[0-9]*)$//')

# 元のファイル名と同じなら（末尾に数字等がなかった）スキップ
if [[ "$base_stripped" == "$basename_noext" ]]; then
  exit 0
fi

# 類似ファイルが存在するか確認
similar_files=()
if [[ -n "$extension" ]]; then
  candidate="$dir/$base_stripped.$extension"
else
  candidate="$dir/$base_stripped"
fi

if [[ -f "$candidate" ]]; then
  similar_files+=("$candidate")
fi

# 類似ファイルが見つかった場合、警告を出力
if [[ ${#similar_files[@]} -gt 0 ]]; then
  echo "⚠️ ゴーストファイル警告: 「${basename_full}」は既存ファイル「$(basename "${similar_files[0]}")」の類似名です。既存ファイルの修正ではなく新規作成が本当に意図した操作ですか？ 既存ファイルの編集を検討してください。"
fi

exit 0
