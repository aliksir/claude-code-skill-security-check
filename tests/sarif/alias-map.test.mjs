// id-alias-map.json 生成・マージのテスト
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { writeFileSync, unlinkSync, mkdirSync } from "fs";
import { generateAliasMap, loadAliasMap, mergeAliasMap, saveAliasMap } from "../../lib/sarif/alias-map.mjs";

// テスト用一時ディレクトリ（Node 18 互換）
const __dirname = dirname(fileURLToPath(import.meta.url));
const tmpDir = join(__dirname, "../../.test-tmp");

describe("generateAliasMap", () => {
  it("昇格済みルールから alias エントリを生成する", () => {
    const rules = [
      {
        id: "ATR-SEC-0042",
        properties: { "draft-id": "DRAFT-bandit-sql-injection" },
      },
    ];
    const map = generateAliasMap(rules);
    assert.equal(map["DRAFT-bandit-sql-injection"], "ATR-SEC-0042");
  });

  it("rejected ルールから tombstone エントリを生成する", () => {
    const rules = [
      {
        id: "DRAFT-pda-false-positive",
        properties: { "draft-status": "rejected" },
      },
    ];
    const map = generateAliasMap(rules);
    assert.equal(map["DRAFT-pda-false-positive"], null);
  });

  it("active DRAFT ルールは map に含めない", () => {
    const rules = [
      {
        id: "DRAFT-pda-prompt-leak",
        properties: { "draft-status": "active" },
      },
    ];
    const map = generateAliasMap(rules);
    assert.equal(Object.keys(map).length, 0);
  });

  it("混合ルールを正しく処理する", () => {
    const rules = [
      { id: "ATR-SEC-0042", properties: { "draft-id": "DRAFT-bandit-sql-injection" } },
      { id: "DRAFT-pda-false-positive", properties: { "draft-status": "rejected" } },
      { id: "DRAFT-pda-prompt-leak", properties: { "draft-status": "active" } },
      { id: "ATR-SEC-0001" },
    ];
    const map = generateAliasMap(rules);
    assert.equal(Object.keys(map).length, 2);
    assert.equal(map["DRAFT-bandit-sql-injection"], "ATR-SEC-0042");
    assert.equal(map["DRAFT-pda-false-positive"], null);
  });
});

describe("mergeAliasMap", () => {
  it("新規エントリをマージする", () => {
    const existing = { "DRAFT-a": "ATR-SEC-0001" };
    const incoming = { "DRAFT-b": "ATR-SEC-0002" };
    const merged = mergeAliasMap(existing, incoming);
    assert.equal(merged["DRAFT-a"], "ATR-SEC-0001");
    assert.equal(merged["DRAFT-b"], "ATR-SEC-0002");
  });

  it("既存 tombstone は上書きしない", () => {
    const existing = { "DRAFT-rejected": null };
    const incoming = { "DRAFT-rejected": "ATR-SEC-0099" };
    const merged = mergeAliasMap(existing, incoming);
    // tombstone は保持される
    assert.equal(merged["DRAFT-rejected"], null);
  });

  it("非 tombstone は更新可能", () => {
    const existing = { "DRAFT-a": "ATR-SEC-0001" };
    const incoming = { "DRAFT-a": "ATR-SEC-0002" };
    const merged = mergeAliasMap(existing, incoming);
    assert.equal(merged["DRAFT-a"], "ATR-SEC-0002");
  });

  it("結果はキー順にソートされる", () => {
    const existing = { "DRAFT-z": "ATR-SEC-0001" };
    const incoming = { "DRAFT-a": "ATR-SEC-0002" };
    const merged = mergeAliasMap(existing, incoming);
    const keys = Object.keys(merged);
    assert.equal(keys[0], "DRAFT-a");
    assert.equal(keys[1], "DRAFT-z");
  });
});

describe("loadAliasMap / saveAliasMap", () => {
  const testFile = join(tmpDir, "test-alias-map.json");

  it("ファイルが存在しない場合は空オブジェクトを返す", () => {
    const map = loadAliasMap(join(tmpDir, "nonexistent.json"));
    assert.deepEqual(map, {});
  });

  it("保存→読込のラウンドトリップが成功する", () => {
    mkdirSync(tmpDir, { recursive: true });
    const original = { "DRAFT-a": "ATR-SEC-0001", "DRAFT-b": null };
    saveAliasMap(original, testFile);
    const loaded = loadAliasMap(testFile);
    assert.deepEqual(loaded, original);
    unlinkSync(testFile);
  });
});
