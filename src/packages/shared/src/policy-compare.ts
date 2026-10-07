// Hand-written policy comparison and folding over the GENERATED catalogue
// (generated/policy.ts <- src/packages/core/src/policy/mod.rs). The Rust core owns
// the semantics (`field_relaxes`, `fold`, `zero_top_rank`); this module
// recomputes them from POLICY_DIRECTIONS and policyFieldKind so the
// extension never trusts a host's claim about which way a change points,
// and tests/policy-compare.test.ts pins the mirror against the Rust
// semantics (the hostReverifyMs zero-top order and the disabledTools set
// semantics included).

import {
  POLICY_DEFAULTS,
  POLICY_DIRECTIONS,
  POLICY_FIELDS,
  type PolicyDoc,
  type PolicyFieldName,
  type PolicyOverlay,
  type PolicyValues,
  policyFieldKind,
} from "../generated/policy";

/** hostReverifyMs on the permissiveness scale (Rust zero_top_rank): 0 means
 * never re-verify, the MOST permissive value, so it maps to the top before
 * comparing. */
function zeroTopRank(ms: number): number {
  return ms === 0 ? Number.POSITIVE_INFINITY : ms;
}

/** Whether `field` moves toward its permissive pole in `candidate` relative
 * to `anchor` (Rust field_relaxes): one arm per pole, none per field. The
 * kind-typed handle narrows both the direction and the two values together,
 * so no arm can meet a value of another kind. */
export function policyFieldRelaxes(
  field: PolicyFieldName,
  candidate: PolicyValues,
  anchor: PolicyValues,
): boolean {
  const handle = policyFieldKind(field);
  switch (handle.kind) {
    case "bool": {
      const c = candidate[handle.field];
      const a = anchor[handle.field];
      return POLICY_DIRECTIONS[handle.field] === "truePermissive" ? c && !a : !c && a;
    }
    case "ms": {
      const c = candidate[handle.field];
      const a = anchor[handle.field];
      return POLICY_DIRECTIONS[handle.field] === "growsPermissiveZeroTop"
        ? zeroTopRank(c) > zeroTopRank(a)
        : c > a;
    }
    case "toolSet": {
      // Set semantics: dropping ANY anchor entry re-enables that tool,
      // whatever else the candidate adds alongside; duplicates and order
      // carry no meaning.
      const candidateSet = new Set(candidate[handle.field]);
      return anchor[handle.field].some((t) => !candidateSet.has(t));
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

/** Copy `field` from `from` into `into`, by kind, so the array never aliases. */
function copyPolicyField(
  field: PolicyFieldName,
  from: PolicyValues | PolicyDoc,
  into: PolicyValues,
): void {
  const handle = policyFieldKind(field);
  switch (handle.kind) {
    case "bool":
      into[handle.field] = from[handle.field];
      return;
    case "ms":
      into[handle.field] = from[handle.field];
      return;
    case "toolSet":
      into[handle.field] = [...from[handle.field]];
      return;
  }
}

/** The catalogue fields of `source` picked BY NAME into a fresh, unaliased
 * PolicyValues: a verified document detached from its scoping fields
 * (v/revision/touched), or a copy of values. Never a spread of the source
 * object. */
export function policyValuesFrom(source: PolicyValues | PolicyDoc): PolicyValues {
  const out: PolicyValues = { ...POLICY_DEFAULTS };
  for (const f of POLICY_FIELDS) copyPolicyField(f, source, out);
  return out;
}

/** The effective policy: the baseline with the overlay's present entries
 * applied over it (Rust fold). Pure field-wise override, by catalogue name
 * only - never by iterating the overlay object's own keys, so nothing a
 * loosely parsed frame smuggled past the strict overlay schema can be folded
 * in. Whether the overlay actually RESTRICTS is the caller's direction check
 * (relaxedPolicyFields against the baseline), never this function's. */
export function foldPolicyOverlay(baseline: PolicyValues, overlay: PolicyOverlay): PolicyValues {
  const out = policyValuesFrom(baseline);
  for (const f of POLICY_FIELDS) {
    const handle = policyFieldKind(f);
    switch (handle.kind) {
      case "bool": {
        const v = overlay[handle.field];
        if (v !== undefined) out[handle.field] = v;
        break;
      }
      case "ms": {
        const v = overlay[handle.field];
        if (v !== undefined) out[handle.field] = v;
        break;
      }
      case "toolSet": {
        const v = overlay[handle.field];
        if (v !== undefined) out[handle.field] = [...v];
        break;
      }
    }
  }
  return out;
}

/** Field-wise, with disabledTools compared ORDERED although the direction table reads it as a set: both callers in
 * policy-sync.ts are identity tests on the stored record, which a set reading would loosen. The ratchet never uses
 * this (it compares baselineB64 bytes and per-field directions); for the set reading compose relaxedPolicyFields both ways.
 *   writeStoredRecord  -> skips an unchanged rewrite; an order-only difference is a new stored value whose onChanged must fire
 *   sameStoredRecord   -> the commit-end undo's "is this still the record this push wrote?"
 */
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
