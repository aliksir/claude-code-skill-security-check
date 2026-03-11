#!/bin/bash
# Skill Security Check — Update Checker
# 使い方: bash updater/check-update.sh [--force]
#
# --force: キャッシュを無視して即時チェック
#
# 設計方針:
#   - デフォルトOFF。ユーザーが明示的にSessionStartフックを設定した場合のみ自動実行
#   - 自動更新はしない。通知のみ
#   - エラー時はサイレントに終了（ユーザー体験を邪魔しない）
#   - Windows (Git Bash/MSYS) でも動作する

set -euo pipefail

# -------------------------------------------------------------------
# 定数
# -------------------------------------------------------------------

# キャッシュファイルパス
CACHE_FILE="${HOME}/.claude/.skill-security-check-update-cache"

# キャッシュ有効期限（秒）= 24時間
CACHE_TTL=86400

# GitHub raw URL（CHANGELOG.mdのrawコンテンツ）
REMOTE_CHANGELOG_URL="https://raw.githubusercontent.com/aliksir/claude-code-skill-security-check/master/CHANGELOG.md"

# リポジトリURL（通知メッセージ用）
CHANGELOG_WEB_URL="https://github.com/aliksir/claude-code-skill-security-check/blob/master/CHANGELOG.md"

# -------------------------------------------------------------------
# ユーティリティ関数
# -------------------------------------------------------------------

# スクリプトのディレクトリから親ディレクトリ（リポジトリルート）を解決
get_repo_root() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    echo "$(dirname "${script_dir}")"
}

# ローカルCHANGELOG.mdから現行バージョンを取得
get_local_version() {
    local repo_root
    repo_root="$(get_repo_root)"
    local changelog="${repo_root}/CHANGELOG.md"

    if [[ ! -f "${changelog}" ]]; then
        # CHANGELOG.mdが見つからない場合はエラー終了
        return 1
    fi

    # 先頭の "## vX.Y.Z" 行からバージョン番号を抽出
    grep -m1 '^## v' "${changelog}" | sed 's/## v\([^ ]*\).*/\1/'
}

# GitHub APIからリモートバージョンを取得
get_remote_version() {
    # curlが使えない環境ではサイレントに終了
    if ! command -v curl &>/dev/null; then
        return 1
    fi

    local remote_version
    remote_version="$(
        curl -sL --max-time 10 "${REMOTE_CHANGELOG_URL}" 2>/dev/null \
        | grep -m1 '^## v' \
        | sed 's/## v\([^ ]*\).*/\1/'
    )"

    # 取得結果が空の場合は失敗扱い
    if [[ -z "${remote_version}" ]]; then
        return 1
    fi

    echo "${remote_version}"
}

# 現在時刻をUnixタイムスタンプ（秒）で返す
# Windows (Git Bash/MSYS) と Linux/macOS 両方に対応
get_timestamp() {
    # date +%s は Git Bash でも動作する
    date +%s 2>/dev/null || echo "0"
}

# キャッシュが有効かどうか確認（0=有効, 1=無効/期限切れ）
is_cache_valid() {
    if [[ ! -f "${CACHE_FILE}" ]]; then
        return 1
    fi

    local cached_time
    cached_time="$(head -1 "${CACHE_FILE}" 2>/dev/null | tr -d '[:space:]')"

    # タイムスタンプが数値でない場合は無効
    if ! [[ "${cached_time}" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    local now
    now="$(get_timestamp)"
    local age=$(( now - cached_time ))

    if (( age < CACHE_TTL )); then
        return 0  # 有効
    else
        return 1  # 期限切れ
    fi
}

# キャッシュファイルを更新（現在時刻を書き込む）
update_cache() {
    local cache_dir
    cache_dir="$(dirname "${CACHE_FILE}")"

    # キャッシュディレクトリが存在しない場合は作成
    mkdir -p "${cache_dir}" 2>/dev/null || true

    local now
    now="$(get_timestamp)"
    echo "${now}" > "${CACHE_FILE}" 2>/dev/null || true
}

# -------------------------------------------------------------------
# メイン処理
# -------------------------------------------------------------------

main() {
    local force_check=false

    # 引数を解析
    for arg in "$@"; do
        case "${arg}" in
            --force)
                force_check=true
                ;;
        esac
    done

    # キャッシュ確認（--force指定時はスキップ）
    if [[ "${force_check}" == "false" ]] && is_cache_valid; then
        # 24時間以内にチェック済み → スキップ
        exit 0
    fi

    # ローカルバージョン取得
    local local_version
    if ! local_version="$(get_local_version)"; then
        # CHANGELOG.mdが見つからない場合はサイレントに終了
        exit 0
    fi

    if [[ -z "${local_version}" ]]; then
        # バージョン取得失敗はサイレントに終了
        exit 0
    fi

    # リモートバージョン取得
    local remote_version
    if ! remote_version="$(get_remote_version)"; then
        # ネットワーク不通やcurl未インストールはサイレントに終了
        exit 0
    fi

    # キャッシュを更新（チェック完了の記録）
    update_cache

    # バージョン比較（semver: リモートがローカルより新しい場合のみ通知）
    if [[ "${remote_version}" != "${local_version}" ]]; then
        local higher
        higher="$(printf '%s\n%s\n' "${remote_version}" "${local_version}" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)"
        if [[ "${higher}" == "${remote_version}" ]]; then
            echo "" >&2
            echo "🔔 Skill Security Check: 新バージョン v${remote_version} が利用可能です（現在: v${local_version}）" >&2
            echo "   → ${CHANGELOG_WEB_URL}" >&2
            echo "" >&2
        fi
    fi

    exit 0
}

main "$@"
