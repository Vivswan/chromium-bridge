// GENERATED from the Rust core (src/packages/core/src/policy/mod.rs and the
// POLICY_DOMAIN in src/packages/core/src/enclave/challenge.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the policy module, then run
// `moon run gen`.
//
// The host-owned policy contract, TS side (ADR-0032): the signing domain,
// the field catalogue with each field's declared permissive direction, the
// strict Zod validators for the signed document and its detached values,
// the deny-baseline defaults, the strict stored-policy parser, and the
// import-bag salvage helper. The
// extension recomputes every relax/restrict comparison from the direction
// table itself - it never trusts a host's claim about which way a change
// points - and verifies signed baselines under POLICY_DOMAIN against its
// pinned key before strict-parsing the same bytes with PolicyDocSchema.

import { z } from "zod";

// Domain-separation prefix for policy signatures: the enrollment key signs
// UTF8(POLICY_DOMAIN) || 0x00 || doc_bytes. A third domain, distinct from
// the enclave challenge and presence domains (generation fails otherwise),
// so a policy signature can never be replayed as an enrollment or
// per-action presence proof, nor either of those as a policy.
export const POLICY_DOMAIN = "chromium-bridge-policy-v1";

// The policy document schema version. PolicyDocSchema pins it as a literal:
// a newer document is rejected rather than misinterpreted, the same
// fail-closed posture as the Rust parser's deny_unknown_fields.
export const POLICY_DOC_VERSION = 1;

// The JS-safe integer bound (2^53 - 1) on the document's revision counter
// and (Rust-side, via the same JS_SAFE_INT_MAX) its millisecond fields, so
// both sides' parsers read the same numbers.
export const POLICY_REVISION_MAX = 9007199254740991;

// Bounds on disabledTools (Rust DISABLED_TOOLS_MAX_ENTRIES /
// DISABLED_TOOL_NAME_MAX_BYTES), enforced by the schemas below so the two
// sides' parsers stay equivalent and no list can outgrow the host store's
// read cap. The Rust bound counts bytes, this one UTF-16 code units; tool
// names are ASCII identifiers, where the two agree, and elsewhere the Rust
// side is the stricter, fail-closed one.
export const DISABLED_TOOLS_MAX_ENTRIES = 256;
export const DISABLED_TOOL_NAME_MAX_BYTES = 128;

// The host-owned policy fields, in the catalogue's declaration order. An
// unknown name never parses (touched entries ride z.enum over this list),
// so a touched set cannot smuggle a field the catalogue does not own.
export const POLICY_FIELDS = [
  "cdpMode",
  "fileUploadEnabled",
  "handleDialogEnabled",
  "pageEvalEnabled",
  "confirmHighRiskClick",
  "confirmPageEval",
  "touchIdConfirm",
  "confirmTabClose",
  "warnPreciseSnapshot",
  "evalMask",
  "hostReverifyMs",
  "confirmGraceMs",
  "clickToastTimeoutMs",
  "evalToastTimeoutMs",
  "disabledTools",
] as const;

export type PolicyFieldName = (typeof POLICY_FIELDS)[number];

const POLICY_FIELD_SET: ReadonlySet<string> = new Set(POLICY_FIELDS);

export function isPolicyFieldName(field: string): field is PolicyFieldName {
  return POLICY_FIELD_SET.has(field);
}

// A field's declared permissive pole (Rust Direction): the value direction
// that grants capability. "truePermissive"/"falsePermissive" are the
// boolean poles; "growsPermissive" millisecond windows grant as they grow;
// "growsPermissiveZeroTop" is hostReverifyMs's custom order (0 = never
// re-verify = MOST permissive, topping the scale); "shrinksPermissiveSet"
// is disabledTools (dropping an entry re-enables a tool).
export type PolicyDirection =
  | "truePermissive"
  | "falsePermissive"
  | "growsPermissive"
  | "growsPermissiveZeroTop"
  | "shrinksPermissiveSet";

export const POLICY_DIRECTIONS: Readonly<Record<PolicyFieldName, PolicyDirection>> = {
  cdpMode: "truePermissive",
  fileUploadEnabled: "truePermissive",
  handleDialogEnabled: "truePermissive",
  pageEvalEnabled: "truePermissive",
  confirmHighRiskClick: "falsePermissive",
  confirmPageEval: "falsePermissive",
  touchIdConfirm: "falsePermissive",
  confirmTabClose: "falsePermissive",
  warnPreciseSnapshot: "falsePermissive",
  evalMask: "falsePermissive",
  hostReverifyMs: "growsPermissiveZeroTop",
  confirmGraceMs: "growsPermissive",
  clickToastTimeoutMs: "growsPermissive",
  evalToastTimeoutMs: "growsPermissive",
  disabledTools: "shrinksPermissiveSet",
};

// The 15 field values, detached from the document's scoping fields (Rust
// PolicyValues): the shape comparisons and the effective policy work in.
export const PolicyValuesSchema = z.strictObject({
  cdpMode: z.boolean(),
  fileUploadEnabled: z.boolean(),
  handleDialogEnabled: z.boolean(),
  pageEvalEnabled: z.boolean(),
  confirmHighRiskClick: z.boolean(),
  confirmPageEval: z.boolean(),
  touchIdConfirm: z.boolean(),
  confirmTabClose: z.boolean(),
  warnPreciseSnapshot: z.boolean(),
  evalMask: z.boolean(),
  hostReverifyMs: z.int().nonnegative(),
  confirmGraceMs: z.int().nonnegative(),
  clickToastTimeoutMs: z.int().nonnegative(),
  evalToastTimeoutMs: z.int().nonnegative(),
  disabledTools: z.array(z.string().min(1).max(128)).max(256),
});

export type PolicyValues = z.infer<typeof PolicyValuesSchema>;

// The signed policy document (Rust PolicyDoc): the exact bytes the enclave
// signature covers, strict-parsed only AFTER the signature verifies.
// `touched` is the set of fields the producing write explicitly edited,
// inside the signed bytes so a fresh signature warrants relaxation on
// exactly those fields, never on the document at large.
export const PolicyDocSchema = z.strictObject({
  v: z.literal(1),
  revision: z.int().nonnegative().max(POLICY_REVISION_MAX),
  touched: z.array(z.enum(POLICY_FIELDS)),
  cdpMode: z.boolean(),
  fileUploadEnabled: z.boolean(),
  handleDialogEnabled: z.boolean(),
  pageEvalEnabled: z.boolean(),
  confirmHighRiskClick: z.boolean(),
  confirmPageEval: z.boolean(),
  touchIdConfirm: z.boolean(),
  confirmTabClose: z.boolean(),
  warnPreciseSnapshot: z.boolean(),
  evalMask: z.boolean(),
  hostReverifyMs: z.int().nonnegative(),
  confirmGraceMs: z.int().nonnegative(),
  clickToastTimeoutMs: z.int().nonnegative(),
  evalToastTimeoutMs: z.int().nonnegative(),
  disabledTools: z.array(z.string().min(1).max(128)).max(256),
});

export type PolicyDoc = z.infer<typeof PolicyDocSchema>;

// Frozen (including the nested array): salvage hands these instances out as
// fallbacks, so a caller mutating its "copy" must throw instead of quietly
// rewriting the defaults for everyone after it.
export const POLICY_DEFAULTS: Readonly<PolicyValues> = deepFreeze(
  PolicyValuesSchema.parse({
    cdpMode: false,
    fileUploadEnabled: false,
    handleDialogEnabled: false,
    pageEvalEnabled: false,
    confirmHighRiskClick: true,
    confirmPageEval: true,
    touchIdConfirm: true,
    confirmTabClose: true,
    warnPreciseSnapshot: true,
    evalMask: true,
    hostReverifyMs: 0,
    confirmGraceMs: 60000,
    clickToastTimeoutMs: 30000,
    evalToastTimeoutMs: 45000,
    disabledTools: [],
  }),
);

function deepFreeze<T>(value: T): T {
  for (const inner of Object.values(value as object)) {
    if (typeof inner === "object" && inner !== null) deepFreeze(inner);
  }
  return Object.freeze(value);
}

/**
 * Per-field salvage for the LEGACY-SETTINGS IMPORT BAG ONLY (ADR-0032
 * decision 8 / phase 4): the snapshotted chrome.storage bag rides
 * `legacy_settings` to the app's first-run import screen, where a corrupt
 * field falling back to its deny-baseline default is SHOWN to the user and
 * signed under their tap - never silently enforced. A value that fails its
 * own schema falls back to that field's default without discarding the
 * healthy fields around it, and unknown keys are dropped.
 *
 * NEVER parse the stored effective policy with this. Per-field default
 * fallback moves a corrupt field toward its permissive pole relative to a
 * user-restricted policy - a relaxation lever made of garbage, exactly the
 * "garbage in, defaults out" behavior ADR-0032 decision 4 forbids. The
 * stored effective policy is read with parseStoredPolicyValues below.
 */
export function salvagePolicyValues(stored: unknown): PolicyValues {
  const bag: Record<string, unknown> =
    typeof stored === "object" && stored !== null ? (stored as Record<string, unknown>) : {};
  return Object.fromEntries(
    Object.entries(PolicyValuesSchema.shape).map(([key, schema]) => {
      const parsed = schema.safeParse(bag[key]);
      return [key, parsed.success ? parsed.data : POLICY_DEFAULTS[key as PolicyFieldName]];
    }),
  ) as PolicyValues;
}

/**
 * Strict parse of the extension's stored effective policy - phase 3's
 * ratchet anchor and every stored-effective read use THIS. Returns the
 * exact values on a valid bag and `null` on ANY failure (a corrupt field,
 * a non-object, an extra key). `null` means "no stored effective": the
 * deny baseline applies and there is no ratchet state to anchor on
 * (ADR-0032 decision 4) - never a salvage, which would hand a corrupted
 * store a relaxation.
 */
export function parseStoredPolicyValues(stored: unknown): PolicyValues | null {
  const parsed = PolicyValuesSchema.safeParse(stored);
  return parsed.success ? parsed.data : null;
}
