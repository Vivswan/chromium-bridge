// GENERATED from the Rust core (src/packages/core/src/policy/mod.rs and the
// POLICY_DOMAIN in src/packages/core/src/enclave/challenge.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the policy module, then run
// `moon run gen`.
//
// The host-owned policy contract, TS side. The extension recomputes every relax/restrict comparison from the
// direction table itself, never trusting a host's claim about which way a change points, and verifies a signed
// baseline under POLICY_DOMAIN against its pinned key before strict-parsing the same bytes with PolicyDocSchema.

import { z } from "zod";

// The host key signs UTF8(POLICY_DOMAIN) || 0x00 || doc_bytes. Distinct from the host-key challenge domain, so a
// policy signature can never be replayed as a challenge proof, nor a proof as a policy.
export const POLICY_DOMAIN = "chromium-bridge-policy-v1";

// PolicyDocSchema pins this as a literal: a newer document is rejected rather than misinterpreted.
export const POLICY_DOC_VERSION = 1;

// The JS-safe integer bound (2^53 - 1) on the revision counter and, Rust-side via JS_SAFE_INT_MAX, the millisecond
// fields, so both parsers read the same numbers.
export const POLICY_REVISION_MAX = 9007199254740991;

// Bounds on disabledTools, so no list can outgrow the host store's read cap. The Rust bound counts bytes, this one
// UTF-16 code units; tool names are ASCII identifiers, where the two agree, and elsewhere Rust is the stricter side.
export const DISABLED_TOOLS_MAX_ENTRIES = 256;
export const DISABLED_TOOL_NAME_MAX_BYTES = 128;

// In the catalogue's declaration order. PolicyDocSchema's touched entries are an enum over the same names, so a
// touched set cannot smuggle a field the catalogue does not own.
export const POLICY_FIELDS = [
  "cdpMode",
  "fileUploadEnabled",
  "handleDialogEnabled",
  "pageEvalEnabled",
  "confirmHighRiskClick",
  "confirmPageEval",
  "presenceConfirm",
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

// The fields by value kind (Rust FieldKind) and the refinement from a name to its kind-typed handle, so a boolean
// comparison can only ever read a boolean field.
export const BOOL_POLICY_FIELDS = [
  "cdpMode",
  "fileUploadEnabled",
  "handleDialogEnabled",
  "pageEvalEnabled",
  "confirmHighRiskClick",
  "confirmPageEval",
  "presenceConfirm",
  "confirmTabClose",
  "warnPreciseSnapshot",
  "evalMask",
] as const;

export const MS_POLICY_FIELDS = [
  "hostReverifyMs",
  "confirmGraceMs",
  "clickToastTimeoutMs",
  "evalToastTimeoutMs",
] as const;

export const TOOL_SET_POLICY_FIELDS = ["disabledTools"] as const;

export type BoolPolicyField = (typeof BOOL_POLICY_FIELDS)[number];
export type MsPolicyField = (typeof MS_POLICY_FIELDS)[number];
export type ToolSetPolicyField = (typeof TOOL_SET_POLICY_FIELDS)[number];

export type PolicyFieldKind =
  | { kind: "bool"; field: BoolPolicyField }
  | { kind: "ms"; field: MsPolicyField }
  | { kind: "toolSet"; field: ToolSetPolicyField };

export function policyFieldKind(field: PolicyFieldName): PolicyFieldKind {
  switch (field) {
    case "cdpMode":
    case "fileUploadEnabled":
    case "handleDialogEnabled":
    case "pageEvalEnabled":
    case "confirmHighRiskClick":
    case "confirmPageEval":
    case "presenceConfirm":
    case "confirmTabClose":
    case "warnPreciseSnapshot":
    case "evalMask":
      return { kind: "bool", field };
    case "hostReverifyMs":
    case "confirmGraceMs":
    case "clickToastTimeoutMs":
    case "evalToastTimeoutMs":
      return { kind: "ms", field };
    case "disabledTools":
      return { kind: "toolSet", field };
  }
}

// A field's permissive pole (Rust Direction), typed by kind so the table cannot pair a field with a direction of
// another kind.
//   bool    -> "truePermissive" | "falsePermissive" (a skipped confirmation is a grant)
//   ms      -> "growsPermissive" (a longer window grants) | "growsPermissiveZeroTop" (0 = never re-verify = MOST permissive)
//   toolSet -> "shrinksPermissiveSet" (dropping an entry re-enables a tool)
export type BoolPole = "truePermissive" | "falsePermissive";
export type MsOrder = "growsPermissive" | "growsPermissiveZeroTop";
export type PolicyDirection = BoolPole | MsOrder | "shrinksPermissiveSet";

export const POLICY_DIRECTIONS: Readonly<
  Record<BoolPolicyField, BoolPole> &
    Record<MsPolicyField, MsOrder> &
    Record<ToolSetPolicyField, "shrinksPermissiveSet">
> = {
  cdpMode: "truePermissive",
  fileUploadEnabled: "truePermissive",
  handleDialogEnabled: "truePermissive",
  pageEvalEnabled: "truePermissive",
  confirmHighRiskClick: "falsePermissive",
  confirmPageEval: "falsePermissive",
  presenceConfirm: "falsePermissive",
  confirmTabClose: "falsePermissive",
  warnPreciseSnapshot: "falsePermissive",
  evalMask: "falsePermissive",
  hostReverifyMs: "growsPermissiveZeroTop",
  confirmGraceMs: "growsPermissive",
  clickToastTimeoutMs: "growsPermissive",
  evalToastTimeoutMs: "growsPermissive",
  disabledTools: "shrinksPermissiveSet",
};

// The field values without the document's scoping fields (Rust PolicyValues): what comparisons and the effective
// policy work in.
export interface PolicyValues {
  cdpMode: boolean;
  fileUploadEnabled: boolean;
  handleDialogEnabled: boolean;
  pageEvalEnabled: boolean;
  confirmHighRiskClick: boolean;
  confirmPageEval: boolean;
  presenceConfirm: boolean;
  confirmTabClose: boolean;
  warnPreciseSnapshot: boolean;
  evalMask: boolean;
  hostReverifyMs: number;
  confirmGraceMs: number;
  clickToastTimeoutMs: number;
  evalToastTimeoutMs: number;
  /**
   * @maxItems 256
   */
  disabledTools: string[];
}

export const PolicyValuesSchema = z
  .object({
    "cdpMode": z.boolean(),
    "fileUploadEnabled": z.boolean(),
    "handleDialogEnabled": z.boolean(),
    "pageEvalEnabled": z.boolean(),
    "confirmHighRiskClick": z.boolean(),
    "confirmPageEval": z.boolean(),
    "presenceConfirm": z.boolean(),
    "confirmTabClose": z.boolean(),
    "warnPreciseSnapshot": z.boolean(),
    "evalMask": z.boolean(),
    "hostReverifyMs": z.number().int().gte(0),
    "confirmGraceMs": z.number().int().gte(0),
    "clickToastTimeoutMs": z.number().int().gte(0),
    "evalToastTimeoutMs": z.number().int().gte(0),
    "disabledTools": z.array(z.string().min(1).max(128)).max(256),
  })
  .strict() as z.ZodType<PolicyValues>;

// The signed policy document (Rust PolicyDoc), strict-parsed only AFTER the signature verifies. `touched` sits
// inside the signed bytes so a fresh signature warrants relaxation on exactly those fields, never the document at
// large. The revision's bound is POLICY_REVISION_MAX, the millisecond fields' the JS-safe integer.
export interface PolicyDoc {
  v: 1;
  revision: number;
  touched: (
    | "cdpMode"
    | "fileUploadEnabled"
    | "handleDialogEnabled"
    | "pageEvalEnabled"
    | "confirmHighRiskClick"
    | "confirmPageEval"
    | "presenceConfirm"
    | "confirmTabClose"
    | "warnPreciseSnapshot"
    | "evalMask"
    | "hostReverifyMs"
    | "confirmGraceMs"
    | "clickToastTimeoutMs"
    | "evalToastTimeoutMs"
    | "disabledTools"
  )[];
  cdpMode: boolean;
  fileUploadEnabled: boolean;
  handleDialogEnabled: boolean;
  pageEvalEnabled: boolean;
  confirmHighRiskClick: boolean;
  confirmPageEval: boolean;
  presenceConfirm: boolean;
  confirmTabClose: boolean;
  warnPreciseSnapshot: boolean;
  evalMask: boolean;
  hostReverifyMs: number;
  confirmGraceMs: number;
  clickToastTimeoutMs: number;
  evalToastTimeoutMs: number;
  /**
   * @maxItems 256
   */
  disabledTools: string[];
}

export const PolicyDocSchema = z
  .object({
    "v": z.literal(1),
    "revision": z.number().int().gte(0).lte(9007199254740991),
    "touched": z.array(
      z.enum([
        "cdpMode",
        "fileUploadEnabled",
        "handleDialogEnabled",
        "pageEvalEnabled",
        "confirmHighRiskClick",
        "confirmPageEval",
        "presenceConfirm",
        "confirmTabClose",
        "warnPreciseSnapshot",
        "evalMask",
        "hostReverifyMs",
        "confirmGraceMs",
        "clickToastTimeoutMs",
        "evalToastTimeoutMs",
        "disabledTools",
      ]),
    ),
    "cdpMode": z.boolean(),
    "fileUploadEnabled": z.boolean(),
    "handleDialogEnabled": z.boolean(),
    "pageEvalEnabled": z.boolean(),
    "confirmHighRiskClick": z.boolean(),
    "confirmPageEval": z.boolean(),
    "presenceConfirm": z.boolean(),
    "confirmTabClose": z.boolean(),
    "warnPreciseSnapshot": z.boolean(),
    "evalMask": z.boolean(),
    "hostReverifyMs": z.number().int().gte(0),
    "confirmGraceMs": z.number().int().gte(0),
    "clickToastTimeoutMs": z.number().int().gte(0),
    "evalToastTimeoutMs": z.number().int().gte(0),
    "disabledTools": z.array(z.string().min(1).max(128)).max(256),
  })
  .strict() as z.ZodType<PolicyDoc>;

// The unsigned restriction overlay (Rust PolicyOverlay), every field optional under the document's bounds. Strict,
// unlike the loose control-frame wrappers: an overlay field the catalogue does not own fails the whole frame parse.
// Whether a parsed overlay actually RESTRICTS is the consumer's direction check, never this shape's.
export interface PolicyOverlay {
  cdpMode?: boolean;
  fileUploadEnabled?: boolean;
  handleDialogEnabled?: boolean;
  pageEvalEnabled?: boolean;
  confirmHighRiskClick?: boolean;
  confirmPageEval?: boolean;
  presenceConfirm?: boolean;
  confirmTabClose?: boolean;
  warnPreciseSnapshot?: boolean;
  evalMask?: boolean;
  hostReverifyMs?: number;
  confirmGraceMs?: number;
  clickToastTimeoutMs?: number;
  evalToastTimeoutMs?: number;
  /**
   * @maxItems 256
   */
  disabledTools?: string[];
}

export const PolicyOverlaySchema = z
  .object({
    "cdpMode": z.boolean().optional(),
    "fileUploadEnabled": z.boolean().optional(),
    "handleDialogEnabled": z.boolean().optional(),
    "pageEvalEnabled": z.boolean().optional(),
    "confirmHighRiskClick": z.boolean().optional(),
    "confirmPageEval": z.boolean().optional(),
    "presenceConfirm": z.boolean().optional(),
    "confirmTabClose": z.boolean().optional(),
    "warnPreciseSnapshot": z.boolean().optional(),
    "evalMask": z.boolean().optional(),
    "hostReverifyMs": z.number().int().gte(0).optional(),
    "confirmGraceMs": z.number().int().gte(0).optional(),
    "clickToastTimeoutMs": z.number().int().gte(0).optional(),
    "evalToastTimeoutMs": z.number().int().gte(0).optional(),
    "disabledTools": z.array(z.string().min(1).max(128)).max(256).optional(),
  })
  .strict() as z.ZodType<PolicyOverlay>;

// Deep-frozen: the pre-cutover posture hands this instance out as the effective policy, so a caller mutating its
// "copy" must throw instead of rewriting the defaults for everyone after it.
export const POLICY_DEFAULTS: Readonly<PolicyValues> = deepFreeze(
  PolicyValuesSchema.parse({
    cdpMode: false,
    fileUploadEnabled: false,
    handleDialogEnabled: false,
    pageEvalEnabled: false,
    confirmHighRiskClick: true,
    confirmPageEval: true,
    presenceConfirm: true,
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
