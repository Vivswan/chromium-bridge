import { describe, expect, it } from "vitest";
import { formatFingerprint } from "../src/lib/fingerprint";

/** The extension's canonical display form (fingerprintDisplay in
 * src/apps/extension/src/lib/background/enclave-verify.ts): the lowercase
 * keyId hex, grouped in 4-char blocks. The desktop app tells the user the
 * two surfaces must match "block for block", so this pins the desktop
 * formatter to that exact form. */
function extensionDisplay(keyIdHex: string): string {
  return keyIdHex.replace(/(.{4})(?=.)/g, "$1 ");
}

const KEY_ID = "7f3a9c04d2e8b1665f0aa42c9d13e7708b52c6a1f4de09b83c75a2e6d1904bfa";

describe("formatFingerprint", () => {
  it("matches the extension popup block for block", () => {
    expect(formatFingerprint(KEY_ID)).toBe(extensionDisplay(KEY_ID));
  });

  it("normalizes case and separators to the canonical lowercase form", () => {
    expect(formatFingerprint(KEY_ID.toUpperCase())).toBe(extensionDisplay(KEY_ID));
    expect(formatFingerprint("7F3A:9C04")).toBe("7f3a 9c04");
    expect(formatFingerprint("7f3a 9c04")).toBe("7f3a 9c04");
  });

  it("passes non-hex material through untouched", () => {
    expect(formatFingerprint("not-a-fingerprint")).toBe("not-a-fingerprint");
  });
});
