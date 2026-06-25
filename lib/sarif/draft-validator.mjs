// SARIF envelope v1: DRAFT ルール emit 前バリデーション
// issue #24 Q2(a) — tracking-issue URL は初回 emit 前に必須

const DRAFT_PATTERN = /^DRAFT-[a-z]+-[a-z0-9-]+$/;
const ATR_PATTERN = /^ATR-[A-Z]+-[0-9]+$/;

// DRAFT ルールのバリデーション（1件）
export function validateDraftRule(rule) {
  const errors = [];

  if (!rule || !rule.id) {
    return { valid: false, errors: ["ルール ID が未定義"] };
  }

  // ATR ID はバリデーション不要（正式登録済み）
  if (ATR_PATTERN.test(rule.id)) {
    return { valid: true, errors: [] };
  }

  // DRAFT ID のフォーマット検証
  if (!DRAFT_PATTERN.test(rule.id)) {
    errors.push(`不正な ID フォーマット: ${rule.id} (ATR-XXX-NNN または DRAFT-scanner-slug 形式が必要)`);
    return { valid: false, errors };
  }

  // DRAFT の場合は tracking-issue URL 必須（Q2(a)）
  const props = rule.properties || {};
  if (!props["tracking-issue"]) {
    errors.push(`DRAFT ルール ${rule.id} に tracking-issue URL がありません（emit 前に必須）`);
  } else if (!isValidUrl(props["tracking-issue"])) {
    errors.push(`DRAFT ルール ${rule.id} の tracking-issue が有効な URL ではありません: ${props["tracking-issue"]}`);
  }

  // draft-status スロットの存在確認（任意だが推奨）
  if (!props["draft-status"]) {
    errors.push(`DRAFT ルール ${rule.id} に draft-status がありません（CI ゲート構築に推奨）`);
  }

  // draft-status が存在する場合、有効な値か検証
  const validStatuses = ["active", "promoted", "rejected", "stale"];
  if (props["draft-status"] && !validStatuses.includes(props["draft-status"])) {
    errors.push(`DRAFT ルール ${rule.id} の draft-status が不正: ${props["draft-status"]} (${validStatuses.join("/")} のいずれか)`);
  }

  // バリデーション結果（draft-status 欠落は警告扱い、エラーは tracking-issue のみ）
  const trackingErrors = errors.filter(e => e.includes("tracking-issue"));
  return {
    valid: trackingErrors.length === 0,
    errors,
  };
}

// 複数ルールの一括バリデーション
export function validateRules(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    return { valid: false, errors: ["ルール配列が空または未定義"], results: [] };
  }

  const results = rules.map(rule => ({
    ruleId: rule?.id || "(undefined)",
    ...validateDraftRule(rule),
  }));

  const allErrors = results.flatMap(r => r.errors);
  const hasInvalid = results.some(r => !r.valid);

  return {
    valid: !hasInvalid,
    errors: allErrors,
    results,
  };
}

// URL 形式の簡易検証
function isValidUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}
