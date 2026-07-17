// UI -> service worker request helper. The message shapes are the RuntimeMsg
// union validated in the SW router (src/packages/shared/runtime-msg.ts); this is a
// thin promise wrapper the React views call. Every response is treated as
// possibly-undefined (the SW may be asleep or refuse), so callers render the
// empty/blocked state rather than hang.

import { browser } from "wxt/browser";

export async function send<T = Record<string, unknown>>(msg: object): Promise<T | undefined> {
  try {
    return (await browser.runtime.sendMessage(msg)) as T;
  } catch {
    return undefined;
  }
}

export interface EnrollmentStatusView {
  required: boolean;
  platformSupported: boolean;
  state: "unpaired" | "pending" | "pinned" | "compromised";
  blocked: boolean;
  fingerprint?: string;
  pinnedAt?: number;
  lastVerifiedAt?: number;
  compromisedReason?: string;
  lastError?: string;
  paused?: boolean;
  /** ADR-0025: the host-key deletion of an unpair has not been acknowledged
   * yet; it completes on the next host connection. */
  hostRevokePending?: boolean;
}

/** The SW's answer to get_clients (ADR-0025), mirroring
 * lib/background/clients.ts ClientListView. */
export interface ClientListView {
  ok: boolean;
  enrolled?: boolean;
  clients?: Array<{
    name: string;
    anchor: { kind: "hash" | "team_id"; value: string };
    added_unix?: number;
  }>;
  error?: string;
}
