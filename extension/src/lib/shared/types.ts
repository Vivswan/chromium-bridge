// Shared type declarations for the chromium-bridge MV3 extension.
//
// The cross-boundary shapes (envelopes, settings, runtime messages) live in
// @chromium-bridge/shared, inferred from the Zod validators that enforce them
// at runtime - this module re-exports them so extension code keeps one import
// path, and adds the few shapes that are extension-internal (the SW <->
// content-script messaging envelope).

import type { OpArgs } from "@chromium-bridge/shared";

// Inferred from the Zod schemas (packages/shared): the settings bag, the
// bridge request/response envelopes, the envelope-level args union, and the
// popup/options runtime messages.
export type {
  BridgeReq,
  BridgeResp,
  OpArgs,
  RuntimeMsg,
  Settings,
} from "@chromium-bridge/shared";

// The { op, args } envelope content.ts receives via browser.runtime.onMessage.
// This is extension-internal (SW -> content script), not the native-messaging
// wire: op also covers the internal ops (ping / _confirm_toast / _info_toast),
// and args additionally carries their `message` text. The content handlers
// read fields generically; each validates what it needs.
export interface ContentMsg {
  op: string;
  args: OpArgs & { message?: string };
  tabId?: number;
  /** What the SW preflight authorized (confirm/gate.ts): the approved
   * origin (enforced against location.origin before any act) and, for
   * clicks, the approved target descriptor. */
  guard?: { expectOrigin?: string; clickExpect?: import("../dom/page-api").ClickProbe };
}

// The reply a content-script op sends back. Ops return varied payloads, so the
// known control fields are typed and the rest is left open.
export interface PageResponse {
  __error?: string;
  __cancelled?: boolean;
  approved?: boolean;
  [key: string]: unknown;
}
