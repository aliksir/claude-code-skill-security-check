// DRAFT ルールバリデーションのテスト
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validateDraftRule, validateRules } from "../../lib/sarif/draft-validator.mjs";

describe("validateDraftRule", () => {
  it("ATR ID はバリデーション不要で通過する", () => {
    const result = validateDraftRule({ id: "ATR-SEC-0042" });
    assert.equal(result.valid, true);
    assert.equal(result.errors.length, 0);
  });

  it("tracking-issue 付き DRAFT ルールは通過する", () => {
    const result = validateDraftRule({
      id: "DRAFT-bandit-sql-injection",
      properties: {
        "tracking-issue": "https://github.com/aliksir/claude-code-skill-security-check/issues/24",
        "draft-status": "active",
      },
    });
    assert.equal(result.valid, true);
  });

  it("tracking-issue なし DRAFT ルールは失敗する", () => {
    const result = validateDraftRule({
      id: "DRAFT-bandit-sql-injection",
      properties: {},
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes("tracking-issue")));
  });

  it("tracking-issue が無効な URL なら失敗する", () => {
    const result = validateDraftRule({
      id: "DRAFT-bandit-sql-injection",
      properties: { "tracking-issue": "not-a-url" },
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes("有効な URL")));
  });

  it("不正な ID フォーマットは失敗する", () => {
    const result = validateDraftRule({ id: "INVALID-ID-FORMAT" });
    assert.equal(result.valid, false);
    assert.ok(result.errors.some(e => e.includes("不正な ID フォーマット")));
  });

  it("ルール未定義は失敗する", () => {
    const result = validateDraftRule(null);
    assert.equal(result.valid, false);
  });

  it("draft-status なしは警告だがバリデーションは通過する", () => {
    const result = validateDraftRule({
      id: "DRAFT-bandit-sql-injection",
      properties: {
        "tracking-issue": "https://github.com/example/repo/issues/1",
      },
    });
    // tracking-issue があるので valid
    assert.equal(result.valid, true);
    // draft-status 欠落の警告は errors に含まれる
    assert.ok(result.errors.some(e => e.includes("draft-status")));
  });

  it("不正な draft-status 値は警告される", () => {
    const result = validateDraftRule({
      id: "DRAFT-bandit-sql-injection",
      properties: {
        "tracking-issue": "https://github.com/example/repo/issues/1",
        "draft-status": "invalid-status",
      },
    });
    assert.equal(result.valid, true);
    assert.ok(result.errors.some(e => e.includes("draft-status が不正")));
  });
});

describe("validateRules", () => {
  it("全ルールが有効なら valid", () => {
    const result = validateRules([
      { id: "ATR-SEC-0042" },
      {
        id: "DRAFT-pda-prompt-leak",
        properties: {
          "tracking-issue": "https://github.com/example/repo/issues/1",
          "draft-status": "active",
        },
      },
    ]);
    assert.equal(result.valid, true);
  });

  it("1件でも無効なら全体が invalid", () => {
    const result = validateRules([
      { id: "ATR-SEC-0042" },
      { id: "DRAFT-pda-prompt-leak", properties: {} },
    ]);
    assert.equal(result.valid, false);
  });

  it("空配列は invalid", () => {
    const result = validateRules([]);
    assert.equal(result.valid, false);
  });

  it("results に各ルールの個別結果が含まれる", () => {
    const result = validateRules([
      { id: "ATR-SEC-0042" },
      { id: "DRAFT-pda-prompt-leak", properties: {} },
    ]);
    assert.equal(result.results.length, 2);
    assert.equal(result.results[0].valid, true);
    assert.equal(result.results[1].valid, false);
  });
});
