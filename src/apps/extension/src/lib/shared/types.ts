// Shared type declarations for the chromium-bridge MV3 extension.
//
// The cross-boundary shapes (envelopes, settings, runtime messages, and the
// SW <-> content-script messaging contract) live in @chromium-bridge/shared,
// inferred from the Zod validators that enforce them at runtime - this module
// re-exports them so extension code keeps one import path.
//
// ContentMsg is the { op, args } envelope content.ts receives via
// browser.tabs.sendMessage: a discriminated union in which every page-acting
// op carries a REQUIRED guard (the origin the SW's allowlist check and any
// confirmation were based on, plus the approved click descriptor for
// page_click). PageReply is the reply envelope the content script wraps every
// outcome in. Both are parsed with Zod at their boundaries; a message or
// reply outside the union is refused, never interpreted.

export type {
  BridgeReq,
  BridgeResp,
  ContentMsg,
  OpArgs,
  PageReply,
  RuntimeMsg,
  Settings,
} from "@chromium-bridge/shared";
