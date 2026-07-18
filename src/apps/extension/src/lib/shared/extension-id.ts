// The pinned extension ID — the ID Chrome derives from the manifest `key`.
//
// The constant itself is generated from the pinned key in
// src/packages/core/src/identity.rs into @chromium-bridge/shared (identity.gen.ts) by
// `just gen`, so it cannot drift from the wxt.config.ts-generated manifest;
// `scripts/check-extension-id.ts` (a CI gate) re-derives the ID from the key
// and asserts every copy (generated TS, built manifest) agrees. If you
// rotate the key (e.g. to adopt a Chrome Web Store-assigned id), regenerate
// everything together — the gates fail otherwise.
import { PINNED_EXTENSION_ID } from "@chromium-bridge/shared";

export { PINNED_EXTENSION_ID };

export interface IdDiagnosis {
  ok: boolean;
  level: "ok" | "error";
  message: string;
}

/**
 * Pure diagnosis: does the running extension id match the pinned one?
 *
 * The native-messaging host's manifest pins the expected id in
 * `allowed_origins`, so if the loaded extension has a different id, Chrome
 * rejects the native connection and chromium-bridge cannot work. This surfaces
 * that failure loudly at startup instead of leaving the user to guess.
 *
 * We compare ids only — `browser.runtime.getManifest()` strips the `key` field
 * at runtime, so we cannot reliably tell "no key" from "different key" here;
 * the message lists the likely causes instead of asserting one.
 */
export function diagnoseExtensionId(
  runtimeId: string,
  expected: string = PINNED_EXTENSION_ID,
): IdDiagnosis {
  if (runtimeId === expected) {
    return {
      ok: true,
      level: "ok",
      message: `extension id ${runtimeId} matches the pinned id — native messaging will be accepted`,
    };
  }
  return {
    ok: false,
    level: "error",
    message:
      `extension id mismatch: running=${runtimeId} expected=${expected}. ` +
      `The native-messaging host pins the expected id in allowed_origins, so this ` +
      `extension will be REJECTED and chromium-bridge cannot connect. Likely cause: ` +
      `you loaded a build whose manifest lacks the pinned \`key\` (Chrome then derives ` +
      `a path-based id), or a Chrome Web Store build with a store-assigned id. Fix: load ` +
      `the built src/apps/extension/dist that contains the pinned key, or update the pinned ` +
      `id in src/packages/core/src/identity.rs (and regenerate) to match your build.`,
  };
}
