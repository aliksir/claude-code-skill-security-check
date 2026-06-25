// previous-draft-id 追跡のテスト
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join } from "path";
import { writeFileSync, unlinkSync, mkdirSync } from "fs";
import {
  loadDraftState,
  recordPromotion,
  getPreviousDraftId,
  injectPreviousDraftId,
  saveDraftState,
  minorVersionDistance,
} from "../../lib/sarif/draft-tracker.mjs";

const tmpDir = join(import.meta.dirname, "../../.test-tmp");

describe("minorVersionDistance", () => {
  it("同一バージョンは距離 0", () => {
    assert.equal(minorVersionDistance("1.2.0", "1.2.0"), 0);
  });

  it("マイナー +1 は距離 1", () => {
    assert.equal(minorVersionDistance("1.2.0", "1.3.0"), 1);
  });

  it("マイナー +2 は距離 2", () => {
    assert.equal(minorVersionDistance("1.2.0", "1.4.0"), 2);
  });

  it("メジャーが異なれば Infinity", () => {
    assert.equal(minorVersionDistance("1.2.0", "2.0.0"), Infinity);
  });

  it("パッチ差はカウントしない", () => {
    assert.equal(minorVersionDistance("1.2.0", "1.2.5"), 0);
  });

  it("不正なバージョンは Infinity", () => {
    assert.equal(minorVersionDistance("invalid", "1.0.0"), Infinity);
  });
});

describe("recordPromotion", () => {
  it("昇格を記録できる", () => {
    const state = { promotions: {} };
    recordPromotion(state, "DRAFT-bandit-sql-injection", "ATR-SEC-0042", "1.2.0");
    assert.equal(state.promotions["ATR-SEC-0042"].draftId, "DRAFT-bandit-sql-injection");
    assert.equal(state.promotions["ATR-SEC-0042"].promotedVersion, "1.2.0");
  });

  it("必須引数が欠けるとエラー", () => {
    const state = { promotions: {} };
    assert.throws(() => recordPromotion(state, null, "ATR-SEC-0042", "1.0.0"));
    assert.throws(() => recordPromotion(state, "DRAFT-a", null, "1.0.0"));
    assert.throws(() => recordPromotion(state, "DRAFT-a", "ATR-SEC-0042", null));
  });
});

describe("getPreviousDraftId", () => {
  const state = {
    promotions: {
      "ATR-SEC-0042": {
        draftId: "DRAFT-bandit-sql-injection",
        promotedAt: "2026-06-25",
        promotedVersion: "1.2.0",
      },
    },
  };

  it("2 マイナーバージョン以内なら返す", () => {
    assert.equal(getPreviousDraftId(state, "ATR-SEC-0042", "1.3.0"), "DRAFT-bandit-sql-injection");
    assert.equal(getPreviousDraftId(state, "ATR-SEC-0042", "1.4.0"), "DRAFT-bandit-sql-injection");
  });

  it("3 マイナーバージョン以降は null", () => {
    assert.equal(getPreviousDraftId(state, "ATR-SEC-0042", "1.5.0"), null);
  });

  it("同一バージョンでも返す", () => {
    assert.equal(getPreviousDraftId(state, "ATR-SEC-0042", "1.2.0"), "DRAFT-bandit-sql-injection");
  });

  it("未登録の ATR ID は null", () => {
    assert.equal(getPreviousDraftId(state, "ATR-SEC-9999", "1.3.0"), null);
  });

  it("メジャーバージョン変更は null", () => {
    assert.equal(getPreviousDraftId(state, "ATR-SEC-0042", "2.0.0"), null);
  });
});

describe("injectPreviousDraftId", () => {
  it("2 バージョン以内の ATR ルールに previous-draft-id を注入する", () => {
    const state = {
      promotions: {
        "ATR-SEC-0042": {
          draftId: "DRAFT-bandit-sql-injection",
          promotedAt: "2026-06-25",
          promotedVersion: "1.2.0",
        },
      },
    };
    const rules = [
      { id: "ATR-SEC-0042", properties: {} },
      { id: "ATR-SEC-0001", properties: {} },
    ];
    const result = injectPreviousDraftId(rules, state, "1.3.0");
    assert.equal(result[0].properties["previous-draft-id"], "DRAFT-bandit-sql-injection");
    assert.equal(result[1].properties["previous-draft-id"], undefined);
  });

  it("DRAFT ルールには注入しない", () => {
    const state = { promotions: {} };
    const rules = [{ id: "DRAFT-pda-prompt-leak", properties: {} }];
    const result = injectPreviousDraftId(rules, state, "1.0.0");
    assert.equal(result[0].properties["previous-draft-id"], undefined);
  });
});

describe("loadDraftState / saveDraftState", () => {
  const testFile = join(tmpDir, "test-draft-state.json");

  it("ファイル未存在で空 state を返す", () => {
    const state = loadDraftState(join(tmpDir, "nonexistent-state.json"));
    assert.deepEqual(state, { promotions: {} });
  });

  it("保存→読込のラウンドトリップが成功する", () => {
    mkdirSync(tmpDir, { recursive: true });
    const state = { promotions: { "ATR-SEC-0042": { draftId: "DRAFT-a", promotedAt: "2026-06-25", promotedVersion: "1.2.0" } } };
    saveDraftState(state, testFile);
    const loaded = loadDraftState(testFile);
    assert.deepEqual(loaded, state);
    unlinkSync(testFile);
  });
});
