// The hand-written policy comparison/fold helpers (policy-compare.ts) must
// mirror the Rust core's semantics exactly (field_relaxes / fold /
// zero_top_rank in src/packages/core/src/policy/mod.rs): the extension
// recomputes every relax/restrict decision from these, so a divergence is a
// parser-differential on the security boundary. The grant condition under
// each pole is checked over the whole generated catalogue; the two orders a
// naive comparator gets wrong (the hostReverifyMs zero-top order and the
// disabledTools set semantics) are pinned as a case list.

import { describe, expect, test } from "bun:test";
import {
  POLICY_DEFAULTS,
  POLICY_DIRECTIONS,
  POLICY_FIELDS,
  PolicyDocSchema,
  type PolicyFieldName,
  type PolicyValues,
  policyFieldKind,
} from "../src/policy.gen";
import {
  foldPolicyOverlay,
  policyFieldRelaxes,
  policyRelaxes,
  policyValuesEqual,
  policyValuesFrom,
  relaxedPolicyFields,
} from "../src/policy-compare";

function values(overrides: Partial<PolicyValues> = {}): PolicyValues {
  return { ...POLICY_DEFAULTS, disabledTools: [...POLICY_DEFAULTS.disabledTools], ...overrides };
}

/** `field` at its permissive pole and at its restrictive pole, every other
 * field at the deny baseline, read from the generated direction table. */
function poles(field: PolicyFieldName): { lax: PolicyValues; tight: PolicyValues } {
  const handle = policyFieldKind(field);
  switch (handle.kind) {
    case "bool": {
      const grant = POLICY_DIRECTIONS[handle.field] === "truePermissive";
      return { lax: values({ [handle.field]: grant }), tight: values({ [handle.field]: !grant }) };
    }
    case "ms": {
      const zeroTop = POLICY_DIRECTIONS[handle.field] === "growsPermissiveZeroTop";
      return {
        lax: values({ [handle.field]: zeroTop ? 0 : 2 }),
        tight: values({ [handle.field]: 1 }),
      };
    }
    case "toolSet":
      return {
        lax: values({ [handle.field]: [] }),
        tight: values({ [handle.field]: ["page_eval"] }),
      };
  }
}

describe("every field relaxes exactly toward its declared pole", () => {
  for (const field of POLICY_FIELDS) {
    test(field, () => {
      const { lax, tight } = poles(field);
      expect(relaxedPolicyFields(lax, tight)).toEqual([field]);
      expect(relaxedPolicyFields(tight, lax)).toEqual([]);
      expect(policyRelaxes(lax, tight)).toBe(true);
      expect(policyRelaxes(tight, lax)).toBe(false);
    });
  }
});

describe("the orders a naive comparator gets wrong", () => {
  const anchorTools = values({ disabledTools: ["page_eval", "page_upload"] });
  const cases: [string, PolicyFieldName, PolicyValues, PolicyValues, boolean][] = [
    // 0 = never re-verify = MOST permissive, above every positive interval.
    ["reverify 0 over 5000", "hostReverifyMs", values(), values({ hostReverifyMs: 5000 }), true],
    ["reverify 5000 over 0", "hostReverifyMs", values({ hostReverifyMs: 5000 }), values(), false],
    [
      "reverify 9000 over 5000",
      "hostReverifyMs",
      values({ hostReverifyMs: 9000 }),
      values({ hostReverifyMs: 5000 }),
      true,
    ],
    [
      "reverify 5000 over 9000",
      "hostReverifyMs",
      values({ hostReverifyMs: 5000 }),
      values({ hostReverifyMs: 9000 }),
      false,
    ],
    ["reverify 0 over 0", "hostReverifyMs", values(), values(), false],
    // A set: dropping ANY anchor entry relaxes, whatever else the candidate
    // adds; order and duplicates carry no meaning.
    [
      "one tool dropped",
      "disabledTools",
      values({ disabledTools: ["page_eval"] }),
      anchorTools,
      true,
    ],
    [
      "one tool dropped while others are added",
      "disabledTools",
      values({ disabledTools: ["page_eval", "tab_close", "cookies_get"] }),
      anchorTools,
      true,
    ],
    [
      "reordered superset",
      "disabledTools",
      values({ disabledTools: ["page_upload", "page_eval", "tab_close"] }),
      anchorTools,
      false,
    ],
    [
      "reordered with a duplicate",
      "disabledTools",
      values({ disabledTools: ["page_upload", "page_eval", "page_eval"] }),
      anchorTools,
      false,
    ],
  ];
  for (const [name, field, candidate, anchor, expected] of cases) {
    test(name, () => {
      expect(policyFieldRelaxes(field, candidate, anchor)).toBe(expected);
    });
  }
});

describe("relaxes over the whole document", () => {
  test("every relaxed field is named, in catalogue order; equal policies relax nothing", () => {
    expect(policyRelaxes(values(), values())).toBe(false);
    expect(relaxedPolicyFields(values({ cdpMode: true, evalMask: false }), values())).toEqual([
      "cdpMode",
      "evalMask",
    ]);
  });

  test("a pure restriction relaxes nothing, and the anchor relaxes it on exactly those fields", () => {
    const restricted = values({
      confirmGraceMs: 1000,
      hostReverifyMs: 60000,
      disabledTools: ["page_eval"],
    });
    expect(relaxedPolicyFields(restricted, values())).toEqual([]);
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
    expect(
      foldPolicyOverlay(baseline, { pageEvalEnabled: false, disabledTools: ["page_upload"] }),
    ).toEqual(values({ confirmGraceMs: 120000, disabledTools: ["page_upload"] }));
    expect(foldPolicyOverlay(baseline, {})).toEqual(baseline);
  });

  test("folding never aliases its inputs (frozen defaults stay intact)", () => {
    const folded = foldPolicyOverlay(POLICY_DEFAULTS, { disabledTools: ["page_eval"] });
    folded.disabledTools.push("mutated");
    expect(POLICY_DEFAULTS.disabledTools).toEqual([]);
    const kept = foldPolicyOverlay(POLICY_DEFAULTS, {});
    kept.disabledTools.push("mutated");
    expect(POLICY_DEFAULTS.disabledTools).toEqual([]);
  });
});

describe("policyValuesFrom", () => {
  test("strips exactly the scoping fields and copies the array", () => {
    const doc = PolicyDocSchema.parse({
      v: 1,
      revision: 7,
      touched: ["pageEvalEnabled"],
      ...values({ pageEvalEnabled: true, disabledTools: ["page_upload"] }),
    });
    const detached = policyValuesFrom(doc);
    expect(detached).toEqual(values({ pageEvalEnabled: true, disabledTools: ["page_upload"] }));
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
