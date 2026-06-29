// SARIF artifact-digest: SKILL.md の SHA-256 ハッシュを artifacts[] に注入する後処理ステップ
// issue #24 — run.artifacts[] にスキャン対象の SKILL.md ハッシュを付与する

import { createHash } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";

// SKILL.md のバイナリ内容を読み込み SHA-256 ハッシュ（小文字 hex）を返す
function computeSha256(filePath) {
  // バイナリ読み込み（UTF-8 正規化を避けてハッシュを安定させる）
  const content = readFileSync(filePath);
  return createHash("sha256").update(content).digest("hex");
}

// SARIF に artifacts[] を注入して新しいオブジェクトを返す（イミュータブル）
// sarifObject: skill-scanner が出力したパース済み SARIF JSON
// skillDir: SKILL.md を含むスキルディレクトリの絶対パス
export function enrichWithArtifactDigest(sarifObject, skillDir) {
  // SKILL.md のパスを確定
  const skillMdPath = join(skillDir, "SKILL.md");

  // SHA-256 ハッシュを計算（SKILL.md が存在しない場合はエラー）
  let hash;
  try {
    hash = computeSha256(skillMdPath);
  } catch (err) {
    if (err.code === "ENOENT") {
      throw new Error(`SKILL.md が見つかりません: ${skillMdPath}`);
    }
    throw err;
  }

  // artifacts[] エントリを構築（SARIF 2.1.0 仕様準拠）
  const artifacts = [
    {
      location: { uri: "SKILL.md", uriBaseId: "%SRCROOT%" },
      hashes: { "sha-256": hash },
    },
  ];

  // runs[0] を更新しつつ元のオブジェクトを変更しない（スプレッドで複製）
  const updatedRuns = sarifObject.runs.map((run, runIdx) => {
    // runs[0] 以外はそのまま返す
    if (runIdx !== 0) return run;

    // results[] に properties.layer: "content" と locations[].artifactLocation.index: 0 を追加
    const updatedResults = (run.results ?? []).map(result => ({
      ...result,
      properties: { ...(result.properties ?? {}), layer: "content" },
      locations: (result.locations ?? []).map(loc => {
        // physicalLocation.artifactLocation がない場合はそのまま返す
        if (!loc.physicalLocation?.artifactLocation) return loc;
        return {
          ...loc,
          physicalLocation: {
            ...loc.physicalLocation,
            artifactLocation: {
              ...loc.physicalLocation.artifactLocation,
              index: 0,
            },
          },
        };
      }),
    }));

    // artifacts と更新済み results を run に統合
    return {
      ...run,
      artifacts,
      results: updatedResults,
    };
  });

  // 元の sarifObject を変更せず新しいオブジェクトを返す
  return {
    ...sarifObject,
    runs: updatedRuns,
  };
}
