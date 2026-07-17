// Egress masking audit: for BOTH page backends the masking happens once, in
// the SW (egress.ts), so these tables cover every path a page-derived secret
// could take out of the extension: storage_get values (always masked),
// page_eval success values, and page_eval exceptions (a thrown secret must
// not bypass the mask).

import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { maskOpResult } from "@/lib/background/egress";

// Shapes the masking catalogue promises to catch (it is best-effort by
// design - see SECURITY.md - so only promised shapes are asserted).
const SECRETS = {
  jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM",
  hex32: "a".repeat(32),
  digits: "4111111111111111",
  bearer: "bearer: sk-live-abcdef1234567890",
};

beforeEach(() => {
  fakeBrowser.reset();
});

describe("storage_get is ALWAYS masked", () => {
  test("single-key read", async () => {
    for (const secret of Object.values(SECRETS)) {
      const out = (await maskOpResult("storage_get", {
        key: "k",
        found: true,
        value: `wrapped ${secret} wrapped`,
      })) as { value: string };
      expect(out.value).not.toBe(`wrapped ${secret} wrapped`);
      expect(out.value).toContain("••••");
    }
  });

  test("entries dump", async () => {
    const out = (await maskOpResult("storage_get", {
      type: "local",
      entries: { a: SECRETS.jwt, b: "plain short" },
      count: 2,
      truncated: false,
      totalKeys: 2,
    })) as { entries: Record<string, string> };
    expect(out.entries.a).not.toContain(SECRETS.jwt);
    expect(out.entries.b).toBe("plain short");
  });

  test("masks even when evalMask was opted out (independent toggles)", async () => {
    await fakeBrowser.storage.local.set({ evalMask: false });
    const out = (await maskOpResult("storage_get", {
      key: "k",
      found: true,
      value: SECRETS.jwt,
    })) as { value: string };
    expect(out.value).not.toContain(SECRETS.jwt);
  });

  test("not-found and malformed results pass through unchanged", async () => {
    expect(await maskOpResult("storage_get", { key: "k", found: false })).toEqual({
      key: "k",
      found: false,
    });
    expect(await maskOpResult("storage_get", null)).toBeNull();
  });
});

describe("page_eval is masked by default, raw only on explicit opt-out", () => {
  test("success values are masked", async () => {
    const out = await maskOpResult("page_eval", { token: SECRETS.jwt, note: "hi" });
    expect(JSON.stringify(out)).not.toContain(SECRETS.jwt);
    expect((out as { note: string }).note).toBe("hi");
  });

  test("a thrown secret (structured __evalError) cannot bypass the mask", async () => {
    const out = (await maskOpResult("page_eval", {
      __evalError: true,
      name: "Error",
      message: `boom ${SECRETS.jwt}`,
      stack: `Error: boom ${SECRETS.jwt}\n  at <anonymous>:1:1`,
    })) as { message: string; stack: string };
    expect(out.message).not.toContain(SECRETS.jwt);
    expect(out.stack).not.toContain(SECRETS.jwt);
  });

  test("evalMask=false leaves eval results raw", async () => {
    await fakeBrowser.storage.local.set({ evalMask: false });
    const out = await maskOpResult("page_eval", SECRETS.jwt);
    expect(out).toBe(SECRETS.jwt);
  });
});

describe("non-sensitive ops pass through", () => {
  test("page_scroll result is untouched", async () => {
    const result = { scrollY: 100, scrollX: 0 };
    expect(await maskOpResult("page_scroll", result)).toBe(result);
  });
});
