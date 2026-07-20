// GENERATED from the Rust core (src/packages/core/src/tools/catalogue.rs) by
// scripts/gen-ops.ts - DO NOT EDIT. Edit the catalogue, then run `moon run gen`.
//
// The tool catalogue, TS side: op names, policy metadata (risk / scope /
// permission / confirmation), and the per-op Zod arg validators the extension
// enforces at the native-messaging boundary. BridgeCommand (the discriminated
// request union) is INFERRED from the validators, so the compile-time types
// and the runtime checks cannot drift apart.

import { z } from "zod";

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

// Policy metadata, mirrored from the catalogue. Consumed by the policy layer
// (background/policy.ts) - kept as plain data so it stays import-side-effect-free.
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

// Per-op arg validators, derived from each tool's inputSchema (minus the
// server-consumed `browser` routing arg). The extension parses an inbound
// request's args against its op's validator before dispatching - fail closed.
export const OP_ARG_SCHEMAS = {
  list_browsers: z.strictObject({}),
  tab_list: z.strictObject({}),
  tab_focus: z.strictObject({ tabId: z.int() }),
  tab_open: z.strictObject({ url: z.string() }),
  tab_close: z.strictObject({ tabId: z.int() }),
  page_snapshot: z.strictObject({}),
  page_click: z.strictObject({ ref: z.string().optional(), selector: z.string().optional() }),
  page_fill: z.strictObject({
    ref: z.string().optional(),
    selector: z.string().optional(),
    value: z.string(),
  }),
  page_text: z.strictObject({}),
  page_screenshot: z.strictObject({}),
  page_scroll: z.strictObject({ direction: z.string().optional(), pixels: z.int().optional() }),
  page_wait_for: z.strictObject({
    nav: z.boolean().optional(),
    selector: z.string().optional(),
    text: z.string().optional(),
    timeoutMs: z.int().optional(),
  }),
  page_eval: z.strictObject({ code: z.string() }),
  page_snapshot_precise: z.strictObject({ frameId: z.string().optional() }),
  cookie_get: z.strictObject({
    domain: z.string().optional(),
    name: z.string().optional(),
    url: z.string().optional(),
  }),
  storage_get: z.strictObject({ key: z.string().optional(), type: z.string().optional() }),
  page_navigate: z.strictObject({ url: z.string() }),
  page_back: z.strictObject({}),
  page_forward: z.strictObject({}),
  page_reload: z.strictObject({}),
  page_press: z.strictObject({ keys: z.string() }),
  page_hover: z.strictObject({ ref: z.string().optional(), selector: z.string().optional() }),
  page_select: z.strictObject({
    ref: z.string().optional(),
    selector: z.string().optional(),
    value: z.string(),
  }),
  console_get: z.strictObject({ limit: z.int().optional() }),
  page_handle_dialog: z.strictObject({ action: z.string(), promptText: z.string().optional() }),
  page_upload: z.strictObject({ path: z.string(), selector: z.string() }),
} as const satisfies Readonly<Record<OpName, z.ZodType>>;

// Per-op request shapes, inferred from the validators. Discriminated on `op`,
// so consumers (background/dispatch.ts) narrow the args to exactly the fields
// that tool accepts. envelope.ts intersects this with the request envelope to
// form BridgeReq.
export type BridgeCommand = {
  [K in OpName]: { op: K; args: z.infer<(typeof OP_ARG_SCHEMAS)[K]> };
}[OpName];

// The envelope-level args bag: the union of every tool's inputSchema props,
// all optional (the per-op validators enforce required-ness).
export const OpArgsSchema = z.strictObject({
  tabId: z.int().optional(),
  url: z.string().optional(),
  ref: z.string().optional(),
  selector: z.string().optional(),
  value: z.string().optional(),
  direction: z.string().optional(),
  pixels: z.int().optional(),
  nav: z.boolean().optional(),
  text: z.string().optional(),
  timeoutMs: z.int().optional(),
  code: z.string().optional(),
  frameId: z.string().optional(),
  domain: z.string().optional(),
  name: z.string().optional(),
  key: z.string().optional(),
  type: z.string().optional(),
  keys: z.string().optional(),
  limit: z.int().optional(),
  action: z.string().optional(),
  promptText: z.string().optional(),
  path: z.string().optional(),
});

export type OpArgs = z.infer<typeof OpArgsSchema>;
