// GENERATED from the Rust core (src/packages/core/src/tools/catalogue.rs and
// args.rs) by scripts/gen-ops.ts - DO NOT EDIT. Edit the catalogue, then run
// `moon run gen`.
//
// The tool catalogue, TS side. The per-op Zod validators derive from the same Rust args structs the Rust reader
// parses, and BridgeCommand is INFERRED from them, so the compile-time types and the runtime checks cannot drift.

import { z } from "zod";
import type { PolicyFieldName, PolicyValues } from "./policy.gen";

export const OP_NAMES = [
  "list_browsers",
  "tab_list",
  "tab_focus",
  "tab_open",
  "tab_close",
  "page_snapshot",
  "page_click",
  "page_fill",
  "page_text",
  "page_screenshot",
  "page_scroll",
  "page_wait_for",
  "page_eval",
  "page_snapshot_precise",
  "cookie_get",
  "storage_get",
  "page_navigate",
  "page_back",
  "page_forward",
  "page_reload",
  "page_press",
  "page_hover",
  "page_select",
  "console_get",
  "page_handle_dialog",
  "page_upload",
] as const;

export type OpName = (typeof OP_NAMES)[number];

const OP_NAME_SET: ReadonlySet<string> = new Set(OP_NAMES);

export function isOpName(op: string): op is OpName {
  return OP_NAME_SET.has(op);
}

// Plain data, so importing it has no side effect.
export type Risk = "critical" | "high" | "low" | "medium";
export type Scope = "page" | "server" | "tab";
export type Permission = "cookies" | "debugger" | "scripting" | "tabs";
export type Confirmation = "every-call" | "high-risk" | "none" | "warn";

export interface ToolMeta {
  risk: Risk;
  scope: Scope;
  permission: Permission;
  confirmation: Confirmation;
}

export const TOOL_META: Readonly<Record<OpName, ToolMeta>> = {
  list_browsers: {
    risk: "low",
    scope: "server",
    permission: "tabs",
    confirmation: "none",
  },
  tab_list: {
    risk: "low",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  tab_focus: {
    risk: "low",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  tab_open: {
    risk: "medium",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  tab_close: {
    risk: "high",
    scope: "tab",
    permission: "tabs",
    confirmation: "every-call",
  },
  page_snapshot: {
    risk: "low",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_click: {
    risk: "high",
    scope: "page",
    permission: "scripting",
    confirmation: "high-risk",
  },
  page_fill: {
    risk: "high",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_text: {
    risk: "medium",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_screenshot: {
    risk: "medium",
    scope: "page",
    permission: "tabs",
    confirmation: "none",
  },
  page_scroll: {
    risk: "low",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_wait_for: {
    risk: "low",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_eval: {
    risk: "critical",
    scope: "page",
    permission: "scripting",
    confirmation: "every-call",
  },
  page_snapshot_precise: {
    risk: "medium",
    scope: "page",
    permission: "debugger",
    confirmation: "warn",
  },
  cookie_get: {
    risk: "high",
    scope: "tab",
    permission: "cookies",
    confirmation: "none",
  },
  storage_get: {
    risk: "high",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_navigate: {
    risk: "medium",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  page_back: {
    risk: "low",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  page_forward: {
    risk: "low",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  page_reload: {
    risk: "low",
    scope: "tab",
    permission: "tabs",
    confirmation: "none",
  },
  page_press: {
    risk: "high",
    scope: "page",
    permission: "scripting",
    confirmation: "every-call",
  },
  page_hover: {
    risk: "low",
    scope: "page",
    permission: "scripting",
    confirmation: "none",
  },
  page_select: {
    risk: "high",
    scope: "page",
    permission: "scripting",
    confirmation: "every-call",
  },
  console_get: {
    risk: "medium",
    scope: "page",
    permission: "debugger",
    confirmation: "warn",
  },
  page_handle_dialog: {
    risk: "high",
    scope: "page",
    permission: "debugger",
    confirmation: "warn",
  },
  page_upload: {
    risk: "critical",
    scope: "page",
    permission: "debugger",
    confirmation: "every-call",
  },
};

// A grant may only name a boolean policy field, so enforcement's `=== true` reads stay type-honest.
type BooleanPolicyField = {
  [K in PolicyFieldName]: PolicyValues[K] extends boolean ? K : never;
}[PolicyFieldName];

// A tool's own grants (Tool::grants in catalogue.rs), every one required true for the tool to run. The extension's
// handlers check only these; the host is the cdpMode gate (Tool::required_grants adds it for every debugger-backed
// tool).
export const TOOL_GRANTS = {
  list_browsers: [],
  tab_list: [],
  tab_focus: [],
  tab_open: [],
  tab_close: [],
  page_snapshot: [],
  page_click: [],
  page_fill: [],
  page_text: [],
  page_screenshot: [],
  page_scroll: [],
  page_wait_for: [],
  page_eval: ["pageEvalEnabled"],
  page_snapshot_precise: [],
  cookie_get: [],
  storage_get: [],
  page_navigate: [],
  page_back: [],
  page_forward: [],
  page_reload: [],
  page_press: [],
  page_hover: [],
  page_select: [],
  console_get: [],
  page_handle_dialog: ["handleDialogEnabled"],
  page_upload: ["fileUploadEnabled"],
} as const satisfies Readonly<Record<OpName, readonly BooleanPolicyField[]>>;

// The extension parses an inbound request's args against its op's validator before dispatching, fail closed.
export const OP_ARG_SCHEMAS = {
  list_browsers: z.object({}).strict(),
  tab_list: z.object({}).strict(),
  tab_focus: z
    .object({ "tabId": z.number().int().gte(-9007199254740991).lte(9007199254740991) })
    .strict(),
  tab_open: z.object({ "url": z.string() }).strict(),
  tab_close: z
    .object({ "tabId": z.number().int().gte(-9007199254740991).lte(9007199254740991) })
    .strict(),
  page_snapshot: z.object({}).strict(),
  page_click: z
    .object({ "ref": z.string().optional(), "selector": z.string().optional() })
    .strict(),
  page_fill: z
    .object({
      "ref": z.string().optional(),
      "selector": z.string().optional(),
      "value": z.string(),
    })
    .strict(),
  page_text: z.object({}).strict(),
  page_screenshot: z.object({}).strict(),
  page_scroll: z
    .object({
      "direction": z.string().optional(),
      "pixels": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    })
    .strict(),
  page_wait_for: z
    .object({
      "nav": z.boolean().optional(),
      "selector": z.string().optional(),
      "text": z.string().optional(),
      "timeoutMs": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    })
    .strict(),
  page_eval: z.object({ "code": z.string() }).strict(),
  page_snapshot_precise: z.object({ "frameId": z.string().optional() }).strict(),
  cookie_get: z
    .object({
      "domain": z.string().optional(),
      "name": z.string().optional(),
      "url": z.string().optional(),
    })
    .strict(),
  storage_get: z.object({ "key": z.string().optional(), "type": z.string().optional() }).strict(),
  page_navigate: z.object({ "url": z.string() }).strict(),
  page_back: z.object({}).strict(),
  page_forward: z.object({}).strict(),
  page_reload: z.object({}).strict(),
  page_press: z.object({ "keys": z.string() }).strict(),
  page_hover: z
    .object({ "ref": z.string().optional(), "selector": z.string().optional() })
    .strict(),
  page_select: z
    .object({
      "ref": z.string().optional(),
      "selector": z.string().optional(),
      "value": z.string(),
    })
    .strict(),
  console_get: z
    .object({ "limit": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional() })
    .strict(),
  page_handle_dialog: z
    .object({ "action": z.string(), "promptText": z.string().optional() })
    .strict(),
  page_upload: z.object({ "path": z.string(), "selector": z.string() }).strict(),
} as const satisfies Readonly<Record<OpName, z.ZodType>>;

// Discriminated on `op`, so a consumer narrows the args to exactly the fields that tool accepts. envelope.ts
// intersects this with the request envelope to form BridgeReq.
export type BridgeCommand = {
  [K in OpName]: { op: K; args: z.infer<(typeof OP_ARG_SCHEMAS)[K]> };
}[OpName];

// Every tool's args props, all optional; the per-op validators enforce required-ness.
export const OpArgsSchema = z
  .object({
    tabId: z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    url: z.string().optional(),
    ref: z.string().optional(),
    selector: z.string().optional(),
    value: z.string().optional(),
    direction: z.string().optional(),
    pixels: z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    nav: z.boolean().optional(),
    text: z.string().optional(),
    timeoutMs: z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    code: z.string().optional(),
    frameId: z.string().optional(),
    domain: z.string().optional(),
    name: z.string().optional(),
    key: z.string().optional(),
    type: z.string().optional(),
    keys: z.string().optional(),
    limit: z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    action: z.string().optional(),
    promptText: z.string().optional(),
    path: z.string().optional(),
  })
  .strict();

export type OpArgs = z.infer<typeof OpArgsSchema>;
