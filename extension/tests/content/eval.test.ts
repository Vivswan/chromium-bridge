// The content-script eval leg executes and serializes ONLY: the settings
// gate and confirmation run in the SW before the message arrives, and
// masking happens SW-side on egress (tests/background/egress.test.ts). These
// tests pin that division: results (including thrown secrets) come back RAW
// and structurally serialized, ready for the egress mask.

import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { runEval } from "@/lib/content/eval";

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM";

const realElement = (globalThis as any).Element;
const realNode = (globalThis as any).Node;

describe("runEval (content leg)", () => {
  beforeEach(() => {
    (globalThis as any).Element = class {};
    (globalThis as any).Node = class {};
  });

  afterEach(() => {
    (globalThis as any).Element = realElement;
    (globalThis as any).Node = realNode;
  });

  test("returns the serialized result raw (masking is the SW's job)", async () => {
    const out: any = await runEval({ code: `return { token: "${JWT}", n: 2 };` });
    expect(out.token).toBe(JWT);
    expect(out.n).toBe(2);
  });

  test("a thrown error becomes structured __evalError data (raw)", async () => {
    const out: any = await runEval({ code: `throw new Error("boom ${JWT}");` });
    expect(out.__evalError).toBe(true);
    expect(out.name).toBe("Error");
    expect(out.message).toContain(JWT);
  });

  test("a getter that throws during serialization lands in __evalError", async () => {
    const out: any = await runEval({
      code: `const o = {}; Object.defineProperty(o, "x", { enumerable: true, get() { throw new Error("gotcha"); } }); return o;`,
    });
    expect(out.__evalError).toBe(true);
    expect(out.message).toContain("gotcha");
  });

  test("empty code is refused", async () => {
    await expect(runEval({ code: "  " })).rejects.toThrow("page_eval needs non-empty `code`");
  });

  test("serialization handles cycles and exotic types", async () => {
    const out: any = await runEval({
      code: `const a = { n: 1 }; a.self = a; return { a, big: 10n, when: new Date(0) };`,
    });
    expect(out.a.self).toBe("[Circular]");
    expect(out.big).toBe("[BigInt:10]");
    expect(out.when).toEqual({ __Date: "1970-01-01T00:00:00.000Z" });
  });
});
