// The bag-site disabledTools bound (legacy-import.ts, ADR-0032 Phase 5): the
// host drops a `legacy_settings` bag whose compact serialization exceeds its
// 64 KiB cap WHOLE, after send-once has latched - so the bag reader bounds
// the one unbounded legacy field before it rides the wire, measured in
// SERIALIZED BYTES (the unit the host's cap counts). Deliberately NOT in the
// legacy schema itself: the pre-cutover enforcement salvage stays
// byte-identical to the old settings.ts (truncating a deny-list there is the
// permissive direction).

import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { readLegacySettingsBag } from "@/lib/background/legacy-import";

const HOST_BAG_CAP_BYTES = 64 * 1024; // pending_import.rs LEGACY_BAG_MAX_BYTES

beforeEach(() => {
  fakeBrowser.reset();
});

describe("readLegacySettingsBag disabledTools bounds", () => {
  test("real-shaped entries pass through untouched", async () => {
    await fakeBrowser.storage.local.set({ disabledTools: ["page_eval", "page_upload"] });
    const bag = await readLegacySettingsBag();
    expect(bag.disabledTools).toEqual(["page_eval", "page_upload"]);
  });

  test("oversize entries drop individually; the rest survive; the list is capped", async () => {
    const oversize = "x".repeat(1_000);
    const huge = [oversize, "page_eval", ...Array.from({ length: 500 }, (_, i) => `tool_${i}`)];
    await fakeBrowser.storage.local.set({ disabledTools: huge });
    const bag = await readLegacySettingsBag();
    expect(bag.disabledTools).not.toContain(oversize);
    expect(bag.disabledTools[0]).toBe("page_eval");
    expect(bag.disabledTools.length).toBeLessThanOrEqual(256);
  });

  test("a pathological list - including non-ASCII and escape-heavy entries - stays under the host's 64 KiB bag cap", async () => {
    // UTF-16 code-unit counts undercount non-ASCII up to ~3x and ignore JSON
    // escape inflation; the bound measures serialized bytes, so these
    // worst-shape entries must still yield a wire-safe bag.
    // a CJK ideograph via escape (this file stays CJK-free for
    // check-cjk): 1 UTF-16 unit each, 3 UTF-8 bytes each when serialized.
    const cjk = "\u6F22".repeat(60); // 60 units, 180 UTF-8 bytes when serialized
    const escapes = "\u0000".repeat(30); // 30 units, ~180 serialized bytes (\u0000 escapes x30)
    const attack = [
      ...Array.from({ length: 5_000 }, (_, i) => `${i}_${cjk}`),
      ...Array.from({ length: 5_000 }, (_, i) => `${i}_${escapes}`),
      ...Array.from({ length: 5_000 }, (_, i) => `${i}_${"y".repeat(500)}`),
      "page_eval",
    ];
    await fakeBrowser.storage.local.set({ disabledTools: attack });
    const bag = await readLegacySettingsBag();
    // Only entries within the serialized-byte cap survive, count-capped.
    expect(bag.disabledTools).toContain("page_eval");
    expect(bag.disabledTools.length).toBeLessThanOrEqual(256);
    for (const entry of bag.disabledTools) {
      expect(new TextEncoder().encode(JSON.stringify(entry)).length).toBeLessThanOrEqual(128);
    }
    // The whole bag - the thing the host measures - fits the cap with room.
    const wireBytes = new TextEncoder().encode(JSON.stringify(bag)).length;
    expect(wireBytes).toBeLessThan(HOST_BAG_CAP_BYTES);
  });
});
