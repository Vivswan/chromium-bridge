// Hand-written policy comparison and folding over the GENERATED direction
// table (policy.gen.ts <- src/packages/core/src/policy/mod.rs). The Rust
// core owns the semantics (`field_relaxes`, `fold`, `zero_top_rank`); this
// module recomputes them field by field from POLICY_DIRECTIONS so the
// extension never trusts a host's claim about which way a change points
// (ADR-0032 decision 2), and tests/policy-compare.test.ts pins the mirror
// against the Rust semantics (including the hostReverifyMs zero-top order
// and the disabledTools set semantics).

import {
  POLICY_DIRECTIONS,
  POLICY_FIELDS,
  type PolicyDoc,
  type PolicyFieldName,
  type PolicyOverlay,
  type PolicyValues,
} from "./policy.gen";

/** hostReverifyMs on the permissiveness scale (Rust zero_top_rank): 0 means
 * never re-verify, the MOST permissive value, so it maps to the top before
 * comparing. */
function zeroTopRank(ms: number): number {
  return ms === 0 ? Number.POSITIVE_INFINITY : ms;
}

// The direction table pairs each field with a comparison over that field's
// value TYPE; the generated schemas guarantee the pairing, and these guards
// re-assert it at the boundary. Throwing (which refuses the push upstream)
// is the fail-closed reading of an impossible mismatch - returning false
// would read as "does not relax" and fail open.
function asNumber(v: unknown): number {
  if (typeof v !== "number") throw new Error("policy field value does not match its direction");
  return v;
}

function asStringArray(v: unknown): string[] {
  if (!Array.isArray(v) || !v.every((t) => typeof t === "string")) {
    throw new Error("policy field value does not match its direction");
  }
  return v;
}

/** Whether `field` moves toward its permissive pole in `candidate` relative
 * to `anchor` (Rust field_relaxes). Each arm spells out its direction's
 * grant condition. */
export function policyFieldRelaxes(
  field: PolicyFieldName,
  candidate: PolicyValues,
  anchor: PolicyValues,
): boolean {
  const c = candidate[field];
  const a = anchor[field];
  switch (POLICY_DIRECTIONS[field]) {
    case "truePermissive":
      return c === true && a === false;
    case "falsePermissive":
      return c === false && a === true;
    case "growsPermissive":
      return asNumber(c) > asNumber(a);
    case "growsPermissiveZeroTop":
      return zeroTopRank(asNumber(c)) > zeroTopRank(asNumber(a));
    case "shrinksPermissiveSet": {
      // Set semantics: dropping ANY anchor entry re-enables that tool,
      // whatever else the candidate adds alongside; duplicates and order
      // carry no meaning.
      const candidateSet = new Set(asStringArray(c));
      return asStringArray(a).some((t) => !candidateSet.has(t));
    }
  }
}

/** Every field on which `candidate` relaxes `anchor`, in catalogue order.
 * Empty means `candidate` restricts-or-holds everywhere (Rust
 * restricts_or_equal, the exact complement of relaxes). */
export function relaxedPolicyFields(
  candidate: PolicyValues,
  anchor: PolicyValues,
): PolicyFieldName[] {
  return POLICY_FIELDS.filter((f) => policyFieldRelaxes(f, candidate, anchor));
}

/** Whether `candidate` moves ANY field toward its permissive pole relative
 * to `anchor` (Rust relaxes). A relaxation is a capability grant: it needs a
 * fresh signature naming the field in its touched set (pinned lane) or the
 * user's window approval (unpinned lane), never the free restriction lane. */
export function policyRelaxes(candidate: PolicyValues, anchor: PolicyValues): boolean {
  return POLICY_FIELDS.some((f) => policyFieldRelaxes(f, candidate, anchor));
}

/** The effective policy: the baseline with the overlay's present entries
 * applied over it (Rust fold). Pure field-wise override, by catalogue name
 * only - never by iterating the overlay object's own keys, so nothing an
 * R5-loose frame smuggled past the strict overlay schema can be folded in.
 * Whether the overlay actually RESTRICTS is the caller's direction check
 * (relaxedPolicyFields against the baseline), never this function's. */
export function foldPolicyOverlay(baseline: PolicyValues, overlay: PolicyOverlay): PolicyValues {
  const out: PolicyValues = { ...baseline, disabledTools: [...baseline.disabledTools] };
  for (const f of POLICY_FIELDS) {
    const v = overlay[f];
    if (v === undefined) continue;
    (out as Record<PolicyFieldName, PolicyValues[PolicyFieldName]>)[f] = Array.isArray(v)
      ? [...v]
      : v;
  }
  return out;
}

/** The 15 field values of a verified document, detached from its scoping
 * fields (v/revision/touched) - picked explicitly BY NAME, never by
 * spreading the document object. */
export function policyValuesFromDoc(doc: PolicyDoc): PolicyValues {
  return {
    cdpMode: doc.cdpMode,
    fileUploadEnabled: doc.fileUploadEnabled,
    handleDialogEnabled: doc.handleDialogEnabled,
    pageEvalEnabled: doc.pageEvalEnabled,
    confirmHighRiskClick: doc.confirmHighRiskClick,
    confirmPageEval: doc.confirmPageEval,
    touchIdConfirm: doc.touchIdConfirm,
    confirmTabClose: doc.confirmTabClose,
    warnPreciseSnapshot: doc.warnPreciseSnapshot,
    evalMask: doc.evalMask,
    hostReverifyMs: doc.hostReverifyMs,
    confirmGraceMs: doc.confirmGraceMs,
    clickToastTimeoutMs: doc.clickToastTimeoutMs,
    evalToastTimeoutMs: doc.evalToastTimeoutMs,
    disabledTools: [...doc.disabledTools],
  };
}

/** Field-wise equality over the 15 policy values (disabledTools compared
 * element-wise): the unchanged-write suppression's comparator, deliberately
 * not JSON.stringify (key order is not part of the contract). */
export function policyValuesEqual(a: PolicyValues, b: PolicyValues): boolean {
  return POLICY_FIELDS.every((f) => {
    const va = a[f];
    const vb = b[f];
    if (Array.isArray(va) && Array.isArray(vb)) {
      return va.length === vb.length && va.every((t, i) => t === vb[i]);
    }
    return va === vb;
  });
}
