// artifact-digest のテスト: SKILL.md SHA-256 注入と locations index 付与
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { createHash } from "crypto";
import { enrichWithArtifactDigest } from "../../lib/sarif/artifact-digest.mjs";

// Node 18 互換のディレクトリ解決
const __dirname = dirname(fileURLToPath(import.meta.url));
const tmpDir = join(__dirname, "../../.test-tmp/artifact-digest");

// テスト用の最小限 SARIF オブジェクトを生成するヘルパー
function makeSarif(results = []) {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "skill-scanner", version: "0.1.0" } },
        results,
      },
    ],
  };
}

// テスト開始前に一時ディレクトリを作成
mkdirSync(tmpDir, { recursive: true });

describe("enrichWithArtifactDigest", () => {
  it("正常系: artifacts[0].hashes[sha-256] が SKILL.md の正しいハッシュになる", () => {
    const skillMdPath = join(tmpDir, "SKILL.md");
    writeFileSync(skillMdPath, "# テストスキル\nこれはテスト用の SKILL.md です", "utf-8");

    // 実装と同じ方法（バイナリ読み込み）で期待ハッシュを計算
    const expectedHash = createHash("sha256").update(readFileSync(skillMdPath)).digest("hex");

    const sarif = makeSarif();
    const result = enrichWithArtifactDigest(sarif, tmpDir);

    // artifacts の構造と値を検証
    assert.equal(result.runs[0].artifacts.length, 1);
    assert.equal(result.runs[0].artifacts[0].hashes["sha-256"], expectedHash);
    assert.equal(result.runs[0].artifacts[0].location.uri, "SKILL.md");
    assert.equal(result.runs[0].artifacts[0].location.uriBaseId, "%SRCROOT%");

    rmSync(skillMdPath);
  });

  it("正常系: results[].locations に index: 0 が追加され既存の uri/uriBaseId が維持される", () => {
    const skillMdPath = join(tmpDir, "SKILL.md");
    writeFileSync(skillMdPath, "# インデックステスト", "utf-8");

    // physicalLocation.artifactLocation を持つ result を含む SARIF を用意
    const sarif = makeSarif([
      {
        ruleId: "DRAFT-test-rule",
        message: { text: "テスト検出" },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: "SKILL.md",
                uriBaseId: "%SRCROOT%",
              },
              region: { startLine: 10 },
            },
          },
        ],
      },
    ]);

    const result = enrichWithArtifactDigest(sarif, tmpDir);
    const artLoc = result.runs[0].results[0].locations[0].physicalLocation.artifactLocation;

    // index: 0 が追加されていることを確認
    assert.equal(artLoc.index, 0);
    // 既存の uri と uriBaseId が維持されていることを確認
    assert.equal(artLoc.uri, "SKILL.md");
    assert.equal(artLoc.uriBaseId, "%SRCROOT%");
    // region 等の他フィールドが維持されていることを確認
    assert.equal(result.runs[0].results[0].locations[0].physicalLocation.region.startLine, 10);

    rmSync(skillMdPath);
  });

  it("異常系: SKILL.md が存在しないディレクトリでエラーがスローされる", () => {
    // SKILL.md を含まない空ディレクトリを作成
    const emptyDir = join(tmpDir, "empty-skill");
    mkdirSync(emptyDir, { recursive: true });

    const sarif = makeSarif();

    // SKILL.md が見つからない場合はエラーがスローされるはず
    assert.throws(
      () => enrichWithArtifactDigest(sarif, emptyDir),
      /SKILL\.md/
    );
  });

  it("イミュータブル: 元のオブジェクトが変更されていない", () => {
    const skillMdPath = join(tmpDir, "SKILL.md");
    writeFileSync(skillMdPath, "# イミュータブルテスト", "utf-8");

    const original = makeSarif();
    const originalRun0Ref = original.runs[0];

    enrichWithArtifactDigest(original, tmpDir);

    // 元の runs[0] に artifacts が追加されていないことを確認
    assert.equal(original.runs[0].artifacts, undefined);
    // runs[0] の参照が変わっていないことを確認（スプレッドで別オブジェクト）
    assert.equal(original.runs[0], originalRun0Ref);
    // runs 配列の長さが変わっていないことを確認
    assert.equal(original.runs.length, 1);

    rmSync(skillMdPath);
  });

  it("envelope: 各 result に properties.layer = 'content' が付与され既存 properties が維持される", () => {
    const skillMdPath = join(tmpDir, "SKILL.md");
    writeFileSync(skillMdPath, "# レイヤーテスト", "utf-8");

    // 既存の properties を持つ result を含む SARIF を用意
    const sarif = makeSarif([
      {
        ruleId: "DRAFT-test-rule",
        message: { text: "テスト検出" },
        properties: { tags: ["security"] },
      },
    ]);

    const result = enrichWithArtifactDigest(sarif, tmpDir);
    const props = result.runs[0].results[0].properties;

    // envelope レイヤーが付与されていることを確認
    assert.equal(props.layer, "content");
    // 既存の properties が維持されていることを確認
    assert.deepEqual(props.tags, ["security"]);

    rmSync(skillMdPath);
  });
});
