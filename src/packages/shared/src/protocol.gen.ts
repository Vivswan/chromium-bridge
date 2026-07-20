// GENERATED from the Rust core (src/packages/core/src/protocol.rs and
// src/packages/core/src/tools/capabilities.rs) by scripts/gen-ops.ts - DO NOT EDIT.
// Run `moon run gen`.

// The INTERNAL bridge protocol version (MCP server <-> native host <->
// extension). Not the MCP JSON-RPC version and not the extension release
// version; bumped only when the bridge wire contract changes incompatibly.
export const BRIDGE_PROTOCOL_VERSION = 1;

// The capability groupings for connection-time negotiation: each capability
// covers a set of tools sharing a Chrome permission. On connect the extension
// advertises which capability ids are actually available; a tool is callable
// only if its capability is advertised.
export interface CapabilityInfo {
  id: string;
  permissions: readonly string[];
  tools: readonly string[];
}

export const CAPABILITIES: readonly CapabilityInfo[] = [
  {
    id: "tab_control",
    permissions: ["tabs"],
    tools: [
      "tab_list",
      "tab_focus",
      "tab_open",
      "tab_close",
      "page_screenshot",
      "page_navigate",
      "page_back",
      "page_forward",
      "page_reload",
    ],
  },
  {
    id: "page_snapshot",
    permissions: ["scripting"],
    tools: ["page_snapshot"],
  },
  {
    id: "page_snapshot_precise",
    permissions: ["debugger"],
    tools: ["page_snapshot_precise"],
  },
  {
    id: "page_interact",
    permissions: ["scripting"],
    tools: [
      "page_click",
      "page_fill",
      "page_press",
      "page_hover",
      "page_select",
      "page_scroll",
      "page_wait_for",
    ],
  },
  {
    id: "page_read",
    permissions: ["scripting"],
    tools: ["page_text"],
  },
  {
    id: "page_eval",
    permissions: ["scripting"],
    tools: ["page_eval"],
  },
  {
    id: "cookie_read",
    permissions: ["cookies"],
    tools: ["cookie_get"],
  },
  {
    id: "storage_read",
    permissions: ["scripting"],
    tools: ["storage_get"],
  },
  {
    id: "console_read",
    permissions: ["debugger"],
    tools: ["console_get"],
  },
  {
    id: "dialog_control",
    permissions: ["debugger"],
    tools: ["page_handle_dialog"],
  },
  {
    id: "file_upload",
    permissions: ["debugger"],
    tools: ["page_upload"],
  },
];
