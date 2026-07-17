// GENERATED from contracts/tools.json by scripts/gen-ops.mjs — DO NOT EDIT.
// Edit the contract, then run `make gen` (or `node scripts/gen-ops.mjs`).
//
// The tool catalogue, JS side: op names + Chinese UI labels for the options
// page, policy metadata (risk / scope / permission / confirmation), and the
// per-tool request shapes (BridgeCommand, derived from each inputSchema).
// tools.rs is verified against the same contract in `cargo test`.

export interface ToolInfo {
  op: string;
  desc: string;
}

export const TOOLS: ToolInfo[] = [
  { op: "list_browsers", desc: "列出已连接的浏览器" },
  { op: "tab_list", desc: "列出所有标签页" },
  { op: "tab_focus", desc: "切换到指定标签页" },
  { op: "tab_open", desc: "打开新标签页(需白名单)" },
  { op: "tab_close", desc: "关闭标签页(带确认)" },
  { op: "page_snapshot", desc: "快照页面可交互元素" },
  { op: "page_click", desc: "点击元素" },
  { op: "page_fill", desc: "填写表单字段" },
  { op: "page_text", desc: "读取页面可见文本" },
  { op: "page_screenshot", desc: "截取可视区域" },
  { op: "page_scroll", desc: "滚动页面" },
  { op: "page_wait_for", desc: "等待条件满足" },
  { op: "page_eval", desc: "执行任意 JS(高危)" },
  { op: "page_snapshot_precise", desc: "精确快照(走 debugger)" },
  { op: "cookie_get", desc: "读取 Cookie(脱敏)" },
  { op: "storage_get", desc: "读取 localStorage/sessionStorage(脱敏)" },
  { op: "page_navigate", desc: "导航当前标签页(需白名单)" },
  { op: "page_back", desc: "后退" },
  { op: "page_forward", desc: "前进" },
  { op: "page_reload", desc: "刷新页面" },
  { op: "page_press", desc: "按键(带确认)" },
  { op: "page_hover", desc: "悬停元素" },
  { op: "page_select", desc: "选择下拉项(带确认)" },
  { op: "console_get", desc: "读取控制台日志(脱敏)" },
  { op: "page_handle_dialog", desc: "响应页面对话框(需开启)" },
  { op: "page_upload", desc: "上传本地文件(极高危,需开启)" },
];

// All op names, for enumeration / consistency checks.
export const OP_NAMES: string[] = TOOLS.map((t) => t.op);

// Policy metadata, mirrored from the contract. Consumed by the policy layer
// (background/policy.ts) — kept as plain data so it stays import-side-effect-free.
export type Risk = "critical" | "high" | "low" | "medium";
export type Scope = "page" | "server" | "tab";
export type Permission = "cookies" | "debugger" | "scripting" | "tabs";
export type Confirmation = "every-call" | "high-risk" | "none" | "page-toast" | "warn";

export interface ToolMeta {
  risk: Risk;
  scope: Scope;
  permission: Permission;
  confirmation: Confirmation;
}

export const TOOL_META: Record<string, ToolMeta> = {
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
    confirmation: "page-toast",
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
    confirmation: "page-toast",
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
    confirmation: "page-toast",
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

// Per-tool request shapes, derived from each tool's inputSchema. Discriminated
// on `op`, so consumers (background/dispatch.ts) narrow the args to exactly the
// fields that tool accepts. shared/types.ts intersects this with the request
// envelope ({ id, tabId? }) to form BridgeReq. Required schema props map to
// required fields; the rest are optional. JSON-Schema string→string,
// integer/number→number, boolean→boolean.
export type BridgeCommand =
  | { op: "list_browsers"; args: Record<string, never> }
  | { op: "tab_list"; args: Record<string, never> }
  | { op: "tab_focus"; args: { tabId: number } }
  | { op: "tab_open"; args: { url: string } }
  | { op: "tab_close"; args: { tabId: number } }
  | { op: "page_snapshot"; args: Record<string, never> }
  | { op: "page_click"; args: { ref?: string; selector?: string } }
  | { op: "page_fill"; args: { ref?: string; selector?: string; value: string } }
  | { op: "page_text"; args: Record<string, never> }
  | { op: "page_screenshot"; args: Record<string, never> }
  | { op: "page_scroll"; args: { direction?: string; pixels?: number } }
  | {
      op: "page_wait_for";
      args: { nav?: boolean; selector?: string; text?: string; timeoutMs?: number };
    }
  | { op: "page_eval"; args: { code: string } }
  | { op: "page_snapshot_precise"; args: { frameId?: string } }
  | { op: "cookie_get"; args: { domain?: string; name?: string; url?: string } }
  | { op: "storage_get"; args: { key?: string; type?: string } }
  | { op: "page_navigate"; args: { url: string } }
  | { op: "page_back"; args: Record<string, never> }
  | { op: "page_forward"; args: Record<string, never> }
  | { op: "page_reload"; args: Record<string, never> }
  | { op: "page_press"; args: { keys: string } }
  | { op: "page_hover"; args: { ref?: string; selector?: string } }
  | { op: "page_select"; args: { ref?: string; selector?: string; value: string } }
  | { op: "console_get"; args: { limit?: number } }
  | { op: "page_handle_dialog"; args: { action: string; promptText?: string } }
  | { op: "page_upload"; args: { selector: string; path: string } };
