// SARIF envelope v1: id-alias-map.json の生成・読込・マージ
// issue #24 Q2(c) — OSV/CVE/GHSA パターンのサイドカーファイル
// tombstone = null で「tried and rejected」を区別

import { readFileSync, writeFileSync } from "fs";

// ルール定義から alias map エントリを生成
export function generateAliasMap(rules) {
  const map = {};

  for (const rule of rules) {
    if (!rule?.id) continue;

    const props = rule.properties || {};

    // ATR ID + draft-id がある場合: 昇格済み
    if (/^ATR-/.test(rule.id) && props["draft-id"]) {
      map[props["draft-id"]] = rule.id;
    }

    // DRAFT ID で draft-status=rejected: tombstone
    if (/^DRAFT-/.test(rule.id) && props["draft-status"] === "rejected") {
      map[rule.id] = null;
    }

    // DRAFT ID で active/stale: まだ未昇格（map には含めない）
  }

  return map;
}

// 既存 alias map ファイルの読み込み
export function loadAliasMap(filePath) {
  try {
    const content = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(content);

    // 基本的な型検証
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("alias map はオブジェクト形式が必要です");
    }

    // 値は string | null のみ許容
    for (const [key, value] of Object.entries(parsed)) {
      if (value !== null && typeof value !== "string") {
        throw new Error(`キー ${key} の値が不正: ${typeof value} (string | null が必要)`);
      }
    }

    return parsed;
  } catch (err) {
    if (err.code === "ENOENT") return {};
    throw err;
  }
}

// 既存 map と新規エントリのマージ（tombstone 保持）
export function mergeAliasMap(existing, incoming) {
  const merged = { ...existing };

  for (const [draftId, atrId] of Object.entries(incoming)) {
    // 既存 tombstone は上書きしない（一度 rejected は確定）
    if (merged[draftId] === null && atrId !== null) {
      continue;
    }
    merged[draftId] = atrId;
  }

  // キーをアルファベット順にソート（diff しやすくする）
  const sorted = {};
  for (const key of Object.keys(merged).sort()) {
    sorted[key] = merged[key];
  }

  return sorted;
}

// alias map をファイルに書き出し
export function saveAliasMap(map, filePath) {
  const content = JSON.stringify(map, null, 2) + "\n";
  writeFileSync(filePath, content, "utf-8");
}
