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

  it("正常系: results[].properties.layer が content に設定される", () => {
    const skillMdPath = join(tmpDir, "SKILL.md");
    writeFileSync(skillMdPath, "# レイヤーテスト", "utf-8");

    // 既存 properties を持つ result と持たない result を用意
    const sarif = makeSarif([
      {
        ruleId: "DRAFT-no-props",
        message: { text: "properties なし" },
        locations: [],
      },
      {
        ruleId: "DRAFT-with-props",
        message: { text: "既存 properties あり" },
        properties: { severity: "high" },
        locations: [],
      },
    ]);

    const result = enrichWithArtifactDigest(sarif, tmpDir);

    // properties なしの result に layer: "content" が追加される
    assert.equal(result.runs[0].results[0].properties.layer, "content");

    // 既存 properties が維持されつつ layer が追加される
    assert.equal(result.runs[0].results[1].properties.layer, "content");
    assert.equal(result.runs[0].results[1].properties.severity, "high");

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
});

// ここから invalid-utf8 fixture のテスト: ハッシュの基準が「生バイト」か「デコード後の文字列」かを見分ける（issue #24）
// fixture の由来と3つの値の出どころは tests/sarif/fixtures/invalid-utf8/README.md を参照
const invalidUtf8FixtureDir = join(__dirname, "fixtures/invalid-utf8");
const invalidUtf8FixturePath = join(invalidUtf8FixtureDir, "SKILL.md");
// 1バイト替えたコピーの置き場（.gitignore 済みの .test-tmp 配下。上のテストの tmpDir とは別にして巻き添えで消さない）
const invalidUtf8TmpDir = join(__dirname, "../../.test-tmp/invalid-utf8-digest");

// ここから公表値（anthropics/skills の issue 492 と skil-lock の PR 41 で示された値。このテストで作り替えない）
// 生バイトに対する SHA-256
const RAW_SHA256 = "0e5f6446b6c4e104a00a87655b759c4a5e5e6031b71f101a59e89156613d365b";
// UTF-8 としてデコードしてから取った SHA-256
const DECODED_SHA256 = "eec1f1320f378b8a269c31429db72e015105571552ebf19e8db161da57808c1d";
// 孤立した 0x80 を 0x81 に替えたときの生バイト SHA-256 の先頭（公表されているのは先頭8桁だけ）
const FLIPPED_RAW_SHA256_PREFIX = "1546f3f1";

// ここから fixture のバイト配置（取得元の blob を実測した値）
const FIXTURE_LENGTH = 577;
// 孤立した継続バイト 0x80 の位置
const LONE_CONTINUATION_OFFSET = 334;
// WTF-8 で符号化した孤立サロゲート U+D800（ED A0 80）の先頭位置
const LONE_SURROGATE_OFFSET = 335;
const LONE_SURROGATE_WTF8 = [0xed, 0xa0, 0x80];

// 生バイトをそのままハッシュする（sha256sum と同じ基準）
function sha256OfBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// UTF-8 としてデコードしてからハッシュする（不正な並びは U+FFFD に置き換わる。見分けたい側の基準）
function sha256OfDecodedString(bytes) {
  return createHash("sha256").update(bytes.toString("utf8"), "utf8").digest("hex");
}

// 孤立した 0x80 の位置を全部返す。直前が ED A0 の 0x80 は孤立サロゲートの一部なので数えない
function findLoneContinuationOffsets(bytes) {
  const offsets = [];
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0x80) continue;
    const insideSurrogate = i >= 2 && bytes[i - 2] === 0xed && bytes[i - 1] === 0xa0;
    if (!insideSurrogate) offsets.push(i);
  }
  return offsets;
}

// lib の実行経路を通して SKILL.md のハッシュを取り出す
// 単体のハッシュ関数は lib から export されていないため、公開されている入口を使う
function digestViaLib(skillDir) {
  return enrichWithArtifactDigest(makeSarif(), skillDir).runs[0].artifacts[0].hashes["sha-256"];
}

// fixture はエンコーディング指定なし（Buffer）で読む。文字列として読むと不正バイトが失われる
const invalidUtf8FixtureBytes = readFileSync(invalidUtf8FixturePath);

describe("invalid-utf8 fixture: ハッシュの基準を見分ける", () => {
  it("fixture のバイト列が壊れていない（長さ・不正な2つの並び・改行変換なし）", () => {
    // checkout で改行が変換されると長さが変わる。値の比較より先にここで気付けるようにする
    assert.equal(
      invalidUtf8FixtureBytes.length,
      FIXTURE_LENGTH,
      "fixture の長さが違う。.gitattributes の -text binary が効いているか確認すること"
    );
    assert.equal(invalidUtf8FixtureBytes.includes(0x0d), false, "fixture に CR が混入している（改行変換の疑い）");

    // 孤立した 0x80 は1つだけで、決まった位置に在る
    assert.deepEqual(findLoneContinuationOffsets(invalidUtf8FixtureBytes), [LONE_CONTINUATION_OFFSET]);

    // 孤立サロゲート ED A0 80 がその直後に在る
    assert.deepEqual(
      [...invalidUtf8FixtureBytes.subarray(LONE_SURROGATE_OFFSET, LONE_SURROGATE_OFFSET + 3)],
      LONE_SURROGATE_WTF8
    );

    // ASCII でないバイトはこの4つだけ（エディタの保存で U+FFFD などに化けるとここで落ちる）
    const nonAsciiOffsets = [];
    invalidUtf8FixtureBytes.forEach((byte, offset) => {
      if (byte >= 0x80) nonAsciiOffsets.push(offset);
    });
    assert.deepEqual(nonAsciiOffsets, [334, 335, 336, 337]);
  });

  it("lib のハッシュは生バイト基準の公表値と一致する", () => {
    // 実装の入口を通した値
    assert.equal(digestViaLib(invalidUtf8FixtureDir), RAW_SHA256);
    // 同じバイト列を直接ハッシュした値（sha256sum 相当）とも一致する
    assert.equal(sha256OfBytes(invalidUtf8FixtureBytes), RAW_SHA256);
  });

  it("デコードしてからハッシュすると別の公表値になり、lib の値とは一致しない", () => {
    const decodedDigest = sha256OfDecodedString(invalidUtf8FixtureBytes);
    assert.equal(decodedDigest, DECODED_SHA256);
    // 2つの基準がこの fixture で食い違うことが、見分けられる根拠
    assert.notEqual(decodedDigest, RAW_SHA256);
    assert.notEqual(digestViaLib(invalidUtf8FixtureDir), DECODED_SHA256);
  });

  it("孤立した 0x80 を 0x81 に替えると、生バイトの値だけが動く", () => {
    // 替えるのは位置 334 の孤立した 0x80。位置 337 の 0x80（ED A0 80 の末尾）には触らない
    const flippedBytes = Buffer.from(invalidUtf8FixtureBytes);
    assert.equal(flippedBytes[LONE_CONTINUATION_OFFSET], 0x80);
    flippedBytes[LONE_CONTINUATION_OFFSET] = 0x81;
    // 元のバイト列は書き換えていない（コピーを替えた）ことと、差が1バイトだけであることを確かめる
    assert.equal(invalidUtf8FixtureBytes[LONE_CONTINUATION_OFFSET], 0x80);
    assert.equal(flippedBytes[LONE_SURROGATE_OFFSET + 2], 0x80);
    assert.equal(flippedBytes.length, invalidUtf8FixtureBytes.length);

    // 生バイト基準: 値が動く（1バイトの差を見分けられる）
    const flippedRawDigest = sha256OfBytes(flippedBytes);
    assert.equal(flippedRawDigest.slice(0, 8), FLIPPED_RAW_SHA256_PREFIX);
    assert.notEqual(flippedRawDigest, RAW_SHA256);

    // デコード後基準: 0x80 も 0x81 も U+FFFD になるので値が動かない（別のファイルが同じ値に潰れる）
    assert.equal(sha256OfDecodedString(flippedBytes), DECODED_SHA256);

    // lib の実行経路でも、替えたファイルは別の値になる（一時ディレクトリへバイナリで書いて通す）
    mkdirSync(invalidUtf8TmpDir, { recursive: true });
    try {
      writeFileSync(join(invalidUtf8TmpDir, "SKILL.md"), flippedBytes);
      assert.equal(digestViaLib(invalidUtf8TmpDir), flippedRawDigest);
    } finally {
      // 一時ファイルは成否に関わらず片付ける
      rmSync(invalidUtf8TmpDir, { recursive: true, force: true });
    }
  });
});
