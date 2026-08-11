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

import { type PolicyValues, StorageReadResultSchema } from "@chromium-bridge/shared";
import { maskSensitive, maskString } from "../shared/masking";
import type { PageOp } from "../shared/page-ops";

export async function maskOpResult(
  op: PageOp,
  result: unknown,
  policy: PolicyValues,
): Promise<unknown> {
  switch (op) {
    case "storage_get":
      return maskStorageResult(result);
    case "page_eval": {
      // Dispatch threads its per-request policy snapshot in (ADR-0032
      // decision 4); the REQUIRED parameter is what holds the invariant
      // (tests start their own decisions via withFreshPolicy).
      return policy.evalMask !== false ? maskSensitive(result) : result;
    }
    default:
      return result;
  }
}

function maskStorageResult(raw: unknown): unknown {
  // Parse before masking (the ADR-0010 gate): a result outside the three
  // known storage_get shapes is REFUSED, never passed through raw - a drifted
  // shape must fail closed instead of carrying unmasked values to the host.
  const parsed = StorageReadResultSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error("storage_get result does not match a known shape - refusing to egress it");
  }
  const result = parsed.data;
  if ("entries" in result) {
    const masked: Record<string, string> = {};
    for (const [k, v] of Object.entries(result.entries)) {
      masked[k] = maskString(v);
    }
    return { ...result, entries: masked };
  }
  if (result.found) {
    return { ...result, value: maskString(result.value) };
  }
  return result;
}
