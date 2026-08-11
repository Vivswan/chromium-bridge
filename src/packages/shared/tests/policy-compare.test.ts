// The hand-written policy comparison/fold helpers (policy-compare.ts) must
// mirror the Rust core's semantics exactly (field_relaxes / fold /
// zero_top_rank in src/packages/core/src/policy/mod.rs): the extension
// recomputes every relax/restrict decision from these, so a divergence is a
// parser-differential on the security boundary. The two arms a naive
// comparator gets wrong are pinned hardest: the hostReverifyMs zero-top
// order and the disabledTools set semantics.

import { describe, expect, test } from "bun:test";
import {
  POLICY_DEFAULTS,
  POLICY_FIELDS,
  PolicyDocSchema,
  type PolicyValues,
} from "../src/policy.gen";
import {
  foldPolicyOverlay,
  policyFieldRelaxes,
  policyRelaxes,
  policyValuesEqual,
  policyValuesFromDoc,
  relaxedPolicyFields,
} from "../src/policy-compare";

function values(overrides: Partial<PolicyValues> = {}): PolicyValues {
  return { ...POLICY_DEFAULTS, disabledTools: [...POLICY_DEFAULTS.disabledTools], ...overrides };
}

describe("boolean poles", () => {
  test("truePermissive: enabling a grant relaxes, disabling restricts", () => {
    expect(policyFieldRelaxes("pageEvalEnabled", values({ pageEvalEnabled: true }), values())).toBe(
      true,
    );
    expect(policyFieldRelaxes("pageEvalEnabled", values(), values({ pageEvalEnabled: true }))).toBe(
      false,
    );
    expect(policyFieldRelaxes("pageEvalEnabled", values(), values())).toBe(false);
  });

  test("falsePermissive: dropping a confirmation relaxes, restoring restricts", () => {
    expect(
      policyFieldRelaxes("confirmPageEval", values({ confirmPageEval: false }), values()),
    ).toBe(true);
    expect(
      policyFieldRelaxes("confirmPageEval", values(), values({ confirmPageEval: false })),
    ).toBe(false);
  });
});

describe("grow-direction fields", () => {
  test("growsPermissive: a longer window relaxes, a shorter one restricts", () => {
    expect(policyFieldRelaxes("confirmGraceMs", values({ confirmGraceMs: 120000 }), values())).toBe(
      true,
    );
    expect(policyFieldRelaxes("confirmGraceMs", values({ confirmGraceMs: 1 }), values())).toBe(
      false,
    );
    expect(policyFieldRelaxes("confirmGraceMs", values(), values())).toBe(false);
  });

  test("hostReverifyMs zero-top: 0 tops the scale (the arm a numeric comparator gets backwards)", () => {
    // 0 = never re-verify = MOST permissive: moving 5000 -> 0 relaxes...
    expect(policyFieldRelaxes("hostReverifyMs", values(), values({ hostReverifyMs: 5000 }))).toBe(
      true,
    );
    // ...and 0 -> any positive interval restricts, never relaxes.
    expect(policyFieldRelaxes("hostReverifyMs", values({ hostReverifyMs: 5000 }), values())).toBe(
      false,
    );
    // Among positive values the numeric order holds: longer = laxer.
    expect(
      policyFieldRelaxes(
        "hostReverifyMs",
        values({ hostReverifyMs: 9000 }),
        values({ hostReverifyMs: 5000 }),
      ),
    ).toBe(true);
    expect(
      policyFieldRelaxes(
        "hostReverifyMs",
        values({ hostReverifyMs: 5000 }),
        values({ hostReverifyMs: 9000 }),
      ),
    ).toBe(false);
    // 0 vs 0: equal, no relax.
    expect(policyFieldRelaxes("hostReverifyMs", values(), values())).toBe(false);
  });
});

describe("disabledTools set semantics", () => {
  test("dropping ANY anchor entry relaxes, whatever else the candidate adds", () => {
    const anchor = values({ disabledTools: ["page_eval", "page_upload"] });
    expect(
      policyFieldRelaxes("disabledTools", values({ disabledTools: ["page_eval"] }), anchor),
    ).toBe(true);
    // Adding new entries alongside the drop does not launder it.
    expect(
      policyFieldRelaxes(
        "disabledTools",
        values({ disabledTools: ["page_eval", "tab_close", "cookies_get"] }),
        anchor,
      ),
    ).toBe(true);
  });

  test("supersets and reorderings never relax; duplicates carry no meaning", () => {
    const anchor = values({ disabledTools: ["page_eval", "page_upload"] });
    expect(
      policyFieldRelaxes(
        "disabledTools",
        values({ disabledTools: ["page_upload", "page_eval", "tab_close"] }),
        anchor,
      ),
    ).toBe(false);
    expect(
      policyFieldRelaxes(
        "disabledTools",
        values({ disabledTools: ["page_upload", "page_eval", "page_eval"] }),
        anchor,
      ),
    ).toBe(false);
  });
});

describe("relaxes over the whole document", () => {
  test("any single relaxed field makes the policy relax; equal policies never do", () => {
    expect(policyRelaxes(values(), values())).toBe(false);
    expect(policyRelaxes(values({ cdpMode: true }), values())).toBe(true);
    expect(relaxedPolicyFields(values({ cdpMode: true, evalMask: false }), values())).toEqual([
      "cdpMode",
      "evalMask",
    ]);
  });

  test("a pure restriction relaxes nothing (the complement reading)", () => {
    const restricted = values({
      confirmGraceMs: 1000,
      hostReverifyMs: 60000,
      disabledTools: ["page_eval"],
    });
    expect(policyRelaxes(restricted, values())).toBe(false);
    // And the anchor relaxes relative to it on exactly those fields.
    expect(relaxedPolicyFields(values(), restricted)).toEqual([
      "hostReverifyMs",
      "confirmGraceMs",
      "disabledTools",
    ]);
  });
});

describe("fold", () => {
  test("present overlay entries override, absent ones keep the baseline (Rust fold)", () => {
    const baseline = values({ pageEvalEnabled: true, confirmGraceMs: 120000 });
    const folded = foldPolicyOverlay(baseline, {
      pageEvalEnabled: false,
      disabledTools: ["page_upload"],
    });
    expect(folded.pageEvalEnabled).toBe(false);
    expect(folded.disabledTools).toEqual(["page_upload"]);
    expect(folded.confirmGraceMs).toBe(120000);
    expect(folded.cdpMode).toBe(false);
  });

  test("folding never aliases its inputs (frozen defaults stay intact)", () => {
    const folded = foldPolicyOverlay(POLICY_DEFAULTS, { disabledTools: ["page_eval"] });
    folded.disabledTools.push("mutated");
    expect(POLICY_DEFAULTS.disabledTools).toEqual([]);
    const kept = foldPolicyOverlay(POLICY_DEFAULTS, {});
    kept.disabledTools.push("mutated");
    expect(POLICY_DEFAULTS.disabledTools).toEqual([]);
  });

  test("an empty overlay folds to field-wise equality", () => {
    const baseline = values({ fileUploadEnabled: true, disabledTools: ["a", "b"] });
    expect(policyValuesEqual(foldPolicyOverlay(baseline, {}), baseline)).toBe(true);
  });
});

describe("policyValuesFromDoc", () => {
  test("strips exactly the scoping fields and copies the array", () => {
    const doc = PolicyDocSchema.parse({
      v: 1,
      revision: 7,
      touched: ["pageEvalEnabled"],
      ...values({ pageEvalEnabled: true, disabledTools: ["page_upload"] }),
    });
    const detached = policyValuesFromDoc(doc);
    expect(Object.keys(detached).sort()).toEqual([...POLICY_FIELDS].sort());
    expect(detached.pageEvalEnabled).toBe(true);
    detached.disabledTools.push("mutated");
    expect(doc.disabledTools).toEqual(["page_upload"]);
  });
});

describe("policyValuesEqual", () => {
  test("field-wise, array element-wise; a differing entry breaks equality", () => {
    expect(policyValuesEqual(values(), values())).toBe(true);
    expect(
      policyValuesEqual(values({ disabledTools: ["a"] }), values({ disabledTools: ["a"] })),
    ).toBe(true);
    expect(
      policyValuesEqual(values({ disabledTools: ["a"] }), values({ disabledTools: ["b"] })),
    ).toBe(false);
    expect(policyValuesEqual(values({ evalMask: false }), values())).toBe(false);
  });

  test("disabledTools order breaks equality on purpose (never set-wise)", () => {
    // Pins the deliberate decision documented on policyValuesEqual: its two
    // consumers (the unchanged-write suppression and the commit-end undo's
    // ownership test in policy-sync.ts) need exact stored-value identity, so
    // a reordered list is a DIFFERENT value here even though the direction
    // table reads the field as a set.
    expect(
      policyValuesEqual(
        values({ disabledTools: ["a", "b"] }),
        values({ disabledTools: ["b", "a"] }),
      ),
    ).toBe(false);
    expect(
      policyValuesEqual(
        values({ disabledTools: ["a", "a", "b"] }),
        values({ disabledTools: ["a", "b"] }),
      ),
    ).toBe(false);
  });
});
