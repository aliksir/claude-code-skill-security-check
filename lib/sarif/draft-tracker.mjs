// SARIF envelope v1: previous-draft-id の追跡
// issue #24 Q2(b) — 昇格後 2 マイナーバージョンの間 previous-draft-id を維持

import { readFileSync, writeFileSync } from "fs";

// state ファイルのスキーマ:
// {
//   "promotions": {
//     "ATR-SEC-0042": {
//       "draftId": "DRAFT-bandit-sql-injection",
//       "promotedAt": "2026-06-25",
//       "promotedVersion": "1.2.0"
//     }
//   }
// }

// state ファイルの読み込み
export function loadDraftState(filePath) {
  try {
    const content = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(content);
    return parsed?.promotions ? parsed : { promotions: {} };
  } catch (err) {
    if (err.code === "ENOENT") return { promotions: {} };
    throw err;
  }
}

// DRAFT → ATR 昇格の記録
export function recordPromotion(state, draftId, atrId, version) {
  if (!draftId || !atrId || !version) {
    throw new Error("draftId, atrId, version は全て必須です");
  }

  state.promotions[atrId] = {
    draftId,
    promotedAt: new Date().toISOString().slice(0, 10),
    promotedVersion: version,
  };

  return state;
}

// 2 マイナーバージョン以内なら previous-draft-id を返す
export function getPreviousDraftId(state, atrId, currentVersion) {
  const entry = state.promotions[atrId];
  if (!entry) return null;

  // バージョン距離の計算（マイナーバージョン差）
  const distance = minorVersionDistance(entry.promotedVersion, currentVersion);

  // 2 マイナーバージョン以内なら返す
  if (distance <= 2) {
    return entry.draftId;
  }

  return null;
}

// reportingDescriptor.properties に previous-draft-id を注入
export function injectPreviousDraftId(rules, state, currentVersion) {
  return rules.map(rule => {
    if (!/^ATR-/.test(rule?.id)) return rule;

    const prevDraftId = getPreviousDraftId(state, rule.id, currentVersion);
    if (!prevDraftId) return rule;

    // properties に previous-draft-id を追加
    return {
      ...rule,
      properties: {
        ...(rule.properties || {}),
        "previous-draft-id": prevDraftId,
      },
    };
  });
}

// state ファイルへの保存
export function saveDraftState(state, filePath) {
  const content = JSON.stringify(state, null, 2) + "\n";
  writeFileSync(filePath, content, "utf-8");
}

// マイナーバージョン距離の計算
// "1.2.0" → "1.4.0" = 距離 2
// "1.2.0" → "2.0.0" = 距離 Infinity（メジャー変更は常に期限切れ）
export function minorVersionDistance(fromVersion, toVersion) {
  const from = parseVersion(fromVersion);
  const to = parseVersion(toVersion);

  if (!from || !to) return Infinity;

  // メジャーバージョンが異なる場合は無限距離
  if (from.major !== to.major) return Infinity;

  return to.minor - from.minor;
}

// semver の簡易パース
function parseVersion(version) {
  const match = String(version).match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
  };
}
