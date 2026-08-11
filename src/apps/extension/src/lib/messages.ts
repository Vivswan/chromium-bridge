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

/** The SW's answer to get_enrollment: the SHARED EnrollmentStatus union
 * (lib/enrollment-status.ts) - the same definition the background produces,
 * so the views cannot construct or over-guard field combinations the
 * background never sends. The old hand-written mirror here is gone. */
export type { EnrollmentStatus as EnrollmentStatusView } from "./enrollment-status";

/** The SW's answer to get_clients (ADR-0025), mirroring
 * lib/background/clients.ts ClientListView: success carries the list,
 * failure carries the reason - never both, never neither. */
export type ClientListView =
  | {
      ok: true;
      enrolled: boolean;
      clients: Array<{
        name: string;
        anchor: { kind: "hash" | "team_id"; value: string };
        added_unix?: number;
      }>;
    }
  | { ok: false; error: string };
