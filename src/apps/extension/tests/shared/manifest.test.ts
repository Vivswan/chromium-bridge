// The generated manifest's SECURITY SURFACE, asserted at its source
// (wxt.config.ts). scripts/check-extension-id.ts re-asserts the same surface
// on the BUILT build/extension/chrome-mv3/manifest.json artifact, so drift
// between this
// config and what ships is caught in CI either way.

import { createHash } from "node:crypto";
import { PINNED_EXTENSION_ID } from "@chromium-bridge/shared";
import { describe, expect, test } from "vitest";
import { MANIFEST_PERMISSIONS } from "@/lib/shared/manifest-permissions";
import wxtConfig from "../../wxt.config";

// The manifest is declared as a plain object in wxt.config.ts.
const manifest = wxtConfig.manifest as Record<string, unknown>;

describe("generated manifest security surface", () => {
  test("the pinned key derives exactly the pinned extension ID", () => {
    const key = manifest.key;
    expect(typeof key).toBe("string");
    const hex = createHash("sha256")
      .update(Buffer.from(key as string, "base64"))
      .digest("hex")
      .slice(0, 32);
    const derived = [...hex]
      .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16)))
      .join("");
    expect(derived).toBe(PINNED_EXTENSION_ID);
  });

  test("permissions are exactly the reviewed list - nothing added, nothing dropped", () => {
    expect(manifest.permissions).toEqual([...MANIFEST_PERMISSIONS]);
  });

  test("no install-time host access; <all_urls> stays optional", () => {
    expect(manifest.host_permissions).toEqual([]);
    expect(manifest.optional_host_permissions).toEqual(["<all_urls>"]);
  });

  test("no content script is declared in the manifest (runtime registration only)", () => {
    expect(manifest.content_scripts).toBeUndefined();
  });
});
