// GENERATED from the Rust core (src/packages/core/src/tools/catalogue.rs and
// args.rs) by scripts/gen-ops.ts - DO NOT EDIT. Edit the catalogue, then run
// `moon run gen`.
//
// The tool catalogue, TS side. Each per-op validator is the Zod source json-schema-to-zod wrote from the one JSON
// Schema the Rust args struct emitted, its type json-schema-to-typescript's reading of the same schema, and
// BridgeCommand is built from them, so the compile-time types and the runtime checks have a single source.

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

// Each tool's args as the extension receives them: the type and, below, the validator, both read from the
// same JSON Schema the Rust args struct emitted.
export type ListBrowsersArgs = Record<string, never>;

export type TabListArgs = Record<string, never>;

export interface TabFocusArgs {
  tabId: number;
}

export interface TabOpenArgs {
  url: string;
}

export interface TabCloseArgs {
  tabId: number;
}

export type PageSnapshotArgs = Record<string, never>;

export interface PageClickArgs {
  ref?: string;
  selector?: string;
}

export interface PageFillArgs {
  ref?: string;
  selector?: string;
  value: string;
}

export type PageTextArgs = Record<string, never>;

export type PageScreenshotArgs = Record<string, never>;

export interface PageScrollArgs {
  direction?: string;
  pixels?: number;
}

export interface PageWaitForArgs {
  nav?: boolean;
  selector?: string;
  text?: string;
  timeoutMs?: number;
}

export interface PageEvalArgs {
  code: string;
}

export interface PageSnapshotPreciseArgs {
  frameId?: string;
}

export interface CookieGetArgs {
  domain?: string;
  name?: string;
  url?: string;
}

export interface StorageGetArgs {
  key?: string;
  type?: string;
}

export interface PageNavigateArgs {
  url: string;
}

export type PageBackArgs = Record<string, never>;

export type PageForwardArgs = Record<string, never>;

export type PageReloadArgs = Record<string, never>;

export interface PagePressArgs {
  keys: string;
}

export interface PageHoverArgs {
  ref?: string;
  selector?: string;
}

export interface PageSelectArgs {
  ref?: string;
  selector?: string;
  value: string;
}

export interface ConsoleGetArgs {
  limit?: number;
}

export interface PageHandleDialogArgs {
  action: string;
  promptText?: string;
}

export interface PageUploadArgs {
  path: string;
  selector: string;
}

// The extension parses an inbound request's args against its op's validator before dispatching, fail closed.
export const OP_ARG_SCHEMAS = {
  list_browsers: z.object({}).strict() as z.ZodType<ListBrowsersArgs>,
  tab_list: z.object({}).strict() as z.ZodType<TabListArgs>,
  tab_focus: z
    .object({ "tabId": z.number().int().gte(-9007199254740991).lte(9007199254740991) })
    .strict() as z.ZodType<TabFocusArgs>,
  tab_open: z.object({ "url": z.string() }).strict() as z.ZodType<TabOpenArgs>,
  tab_close: z
    .object({ "tabId": z.number().int().gte(-9007199254740991).lte(9007199254740991) })
    .strict() as z.ZodType<TabCloseArgs>,
  page_snapshot: z.object({}).strict() as z.ZodType<PageSnapshotArgs>,
  page_click: z
    .object({ "ref": z.string().optional(), "selector": z.string().optional() })
    .strict() as z.ZodType<PageClickArgs>,
  page_fill: z
    .object({
      "ref": z.string().optional(),
      "selector": z.string().optional(),
      "value": z.string(),
    })
    .strict() as z.ZodType<PageFillArgs>,
  page_text: z.object({}).strict() as z.ZodType<PageTextArgs>,
  page_screenshot: z.object({}).strict() as z.ZodType<PageScreenshotArgs>,
  page_scroll: z
    .object({
      "direction": z.string().optional(),
      "pixels": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    })
    .strict() as z.ZodType<PageScrollArgs>,
  page_wait_for: z
    .object({
      "nav": z.boolean().optional(),
      "selector": z.string().optional(),
      "text": z.string().optional(),
      "timeoutMs": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    })
    .strict() as z.ZodType<PageWaitForArgs>,
  page_eval: z.object({ "code": z.string() }).strict() as z.ZodType<PageEvalArgs>,
  page_snapshot_precise: z
    .object({ "frameId": z.string().optional() })
    .strict() as z.ZodType<PageSnapshotPreciseArgs>,
  cookie_get: z
    .object({
      "domain": z.string().optional(),
      "name": z.string().optional(),
      "url": z.string().optional(),
    })
    .strict() as z.ZodType<CookieGetArgs>,
  storage_get: z
    .object({ "key": z.string().optional(), "type": z.string().optional() })
    .strict() as z.ZodType<StorageGetArgs>,
  page_navigate: z.object({ "url": z.string() }).strict() as z.ZodType<PageNavigateArgs>,
  page_back: z.object({}).strict() as z.ZodType<PageBackArgs>,
  page_forward: z.object({}).strict() as z.ZodType<PageForwardArgs>,
  page_reload: z.object({}).strict() as z.ZodType<PageReloadArgs>,
  page_press: z.object({ "keys": z.string() }).strict() as z.ZodType<PagePressArgs>,
  page_hover: z
    .object({ "ref": z.string().optional(), "selector": z.string().optional() })
    .strict() as z.ZodType<PageHoverArgs>,
  page_select: z
    .object({
      "ref": z.string().optional(),
      "selector": z.string().optional(),
      "value": z.string(),
    })
    .strict() as z.ZodType<PageSelectArgs>,
  console_get: z
    .object({ "limit": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional() })
    .strict() as z.ZodType<ConsoleGetArgs>,
  page_handle_dialog: z
    .object({ "action": z.string(), "promptText": z.string().optional() })
    .strict() as z.ZodType<PageHandleDialogArgs>,
  page_upload: z
    .object({ "path": z.string(), "selector": z.string() })
    .strict() as z.ZodType<PageUploadArgs>,
} as const satisfies Readonly<Record<OpName, z.ZodType>>;

// Discriminated on `op`, so a consumer narrows the args to exactly the fields that tool accepts. envelope.ts
// intersects this with the request envelope to form BridgeReq.
export type BridgeCommand = {
  [K in OpName]: { op: K; args: z.infer<(typeof OP_ARG_SCHEMAS)[K]> };
}[OpName];

// Every tool's args props, all optional; the per-op validators enforce required-ness.
export interface OpArgs {
  tabId?: number;
  url?: string;
  ref?: string;
  selector?: string;
  value?: string;
  direction?: string;
  pixels?: number;
  nav?: boolean;
  text?: string;
  timeoutMs?: number;
  code?: string;
  frameId?: string;
  domain?: string;
  name?: string;
  key?: string;
  type?: string;
  keys?: string;
  limit?: number;
  action?: string;
  promptText?: string;
  path?: string;
}

export const OpArgsSchema = z
  .object({
    "tabId": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    "url": z.string().optional(),
    "ref": z.string().optional(),
    "selector": z.string().optional(),
    "value": z.string().optional(),
    "direction": z.string().optional(),
    "pixels": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    "nav": z.boolean().optional(),
    "text": z.string().optional(),
    "timeoutMs": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    "code": z.string().optional(),
    "frameId": z.string().optional(),
    "domain": z.string().optional(),
    "name": z.string().optional(),
    "key": z.string().optional(),
    "type": z.string().optional(),
    "keys": z.string().optional(),
    "limit": z.number().int().gte(-9007199254740991).lte(9007199254740991).optional(),
    "action": z.string().optional(),
    "promptText": z.string().optional(),
    "path": z.string().optional(),
  })
  .strict() as z.ZodType<OpArgs>;
