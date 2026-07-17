// Egress masking, applied in ONE place for both page backends: the service
// worker is the last hop before a result leaves the extension for the native
// host, so per-op masking lives here instead of being duplicated in the
// content script and the CDP backend (which used to mask independently and
// could drift).
//
// Policy:
// - storage_get: ALWAYS masked (silent read of Web Storage - ADR-0010),
//   independent of the eval mask toggle.
// - page_eval: masked unless the user opted out (evalMask=false). EVERY
//   field of an eval result passes the gate - the success value and the
//   structured __evalError (name/message/stack) alike, because a page can
//   carry a secret out by throwing it.
// - everything else: passed through (page_text masks passwords/card numbers
//   in the page walk itself; cookie_get masks in cookies.ts).

import { maskSensitive, maskString } from "../shared/masking";
import type { PageOp } from "../shared/page-ops";
import { getSetting } from "../shared/settings";

export async function maskOpResult(op: PageOp, result: unknown): Promise<unknown> {
  switch (op) {
    case "storage_get":
      return maskStorageResult(result);
    case "page_eval": {
      const mask = (await getSetting("evalMask")) !== false;
      return mask ? maskSensitive(result) : result;
    }
    default:
      return result;
  }
}

function maskStorageResult(raw: unknown): unknown {
  if (raw === null || typeof raw !== "object") return raw;
  const rec = raw as Record<string, unknown>;
  if ("entries" in rec && rec.entries && typeof rec.entries === "object") {
    const masked: Record<string, string> = {};
    for (const [k, v] of Object.entries(rec.entries as Record<string, unknown>)) {
      masked[k] = maskString(String(v));
    }
    return { ...rec, entries: masked };
  }
  if (rec.found === true && typeof rec.value === "string") {
    return { ...rec, value: maskString(rec.value) };
  }
  return raw;
}
