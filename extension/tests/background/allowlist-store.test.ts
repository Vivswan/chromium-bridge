// Central allowlist add-validation (defense-in-depth: not UI-only). A
// submitted URL is reduced to a bare origin glob for an http(s) origin;
// anything else is refused so a malformed entry no ensureAllowed check would
// match cannot be seeded from any surface.

import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { addAllow, canonicalOriginGlob, getAllowlist } from "@/lib/background/allowlist-store";

beforeEach(() => {
  fakeBrowser.reset();
});

describe("canonicalOriginGlob", () => {
  test("reduces any http(s) URL to protocol://host/*", () => {
    expect(canonicalOriginGlob("https://example.com/path?q=1")).toBe("https://example.com/*");
    expect(canonicalOriginGlob("http://a.b.example.com:8080/")).toBe(
      "http://a.b.example.com:8080/*",
    );
    expect(canonicalOriginGlob("  https://x.test  ")).toBe("https://x.test/*");
  });

  test("drops embedded credentials", () => {
    expect(canonicalOriginGlob("https://user:pass@example.com/")).toBe("https://example.com/*");
  });

  test("refuses non-http(s) and unparsable input", () => {
    expect(canonicalOriginGlob("file:///etc/passwd")).toBeNull();
    expect(canonicalOriginGlob("javascript:alert(1)")).toBeNull();
    expect(canonicalOriginGlob("not a url")).toBeNull();
    expect(canonicalOriginGlob("")).toBeNull();
    expect(canonicalOriginGlob(123)).toBeNull();
  });
});

describe("addAllow", () => {
  test("persists the canonical glob and reports ok", async () => {
    const r = await addAllow("https://example.com/deep/path");
    expect(r.ok).toBe(true);
    expect(r.list).toEqual(["https://example.com/*"]);
    expect(await getAllowlist()).toEqual(["https://example.com/*"]);
  });

  test("refuses an invalid origin without persisting", async () => {
    const r = await addAllow("file:///x");
    expect(r.ok).toBe(false);
    expect(r.error).toContain("not a valid");
    expect(await getAllowlist()).toEqual([]);
  });

  test("de-duplicates", async () => {
    await addAllow("https://example.com/a");
    const r = await addAllow("https://example.com/b");
    expect(r.list).toEqual(["https://example.com/*"]);
  });
});
