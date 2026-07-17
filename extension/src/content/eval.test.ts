import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { runEval } from "./eval";

// A value shaped like a real credential, so the masking catalogue must catch
// it wherever it egresses (matches masking.ts's JWT pattern).
const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM";

const realChrome = (globalThis as any).chrome;
const realElement = (globalThis as any).Element;
const realNode = (globalThis as any).Node;

// runEval only touches chrome.storage (settings) plus Element/Node instanceof
// checks during serialization; stub those so it runs under bun. confirmPageEval
// is off in every test because the toast needs a real DOM.
function mockSettings(store: Record<string, unknown>) {
  (globalThis as any).chrome = {
    storage: {
      local: {
        get: (key: string, cb: (r: Record<string, unknown>) => void) => cb({ [key]: store[key] }),
      },
    },
  };
}

describe("runEval egress masking", () => {
  beforeEach(() => {
    (globalThis as any).Element = class {};
    (globalThis as any).Node = class {};
  });

  afterEach(() => {
    (globalThis as any).chrome = realChrome;
    (globalThis as any).Element = realElement;
    (globalThis as any).Node = realNode;
  });

  test("a thrown exception carrying a secret egresses masked", async () => {
    mockSettings({ confirmPageEval: false });
    const out: any = await runEval({
      code: `throw new Error("token " + ${JSON.stringify(JWT)});`,
    });
    expect(out.__evalError).toBe(true);
    expect(out.message).not.toContain(JWT);
    expect(out.message).toContain("••••");
    // The stack embeds the message; it must be masked too.
    expect(out.stack).not.toContain(JWT);
  });

  test("a getter that throws during serialization egresses masked, not raw", async () => {
    mockSettings({ confirmPageEval: false });
    // Serialization walks own keys; the getter throws the secret. This used to
    // escape runEval entirely (serialization ran outside the try) and reach
    // the outer message handler unmasked.
    const out: any = await runEval({
      code: `return { get token() { throw new Error(${JSON.stringify(JWT)}); } };`,
    });
    expect(out.__evalError).toBe(true);
    expect(JSON.stringify(out)).not.toContain(JWT);
  });

  test("success values keep being masked", async () => {
    mockSettings({ confirmPageEval: false });
    const out: any = await runEval({
      code: `return { note: "hi", jwt: ${JSON.stringify(JWT)} };`,
    });
    expect(JSON.stringify(out)).not.toContain(JWT);
    expect(out.note).toBe("hi");
  });

  test("evalMask=false (explicit opt-out) returns the exception unmasked", async () => {
    mockSettings({ confirmPageEval: false, evalMask: false });
    const out: any = await runEval({
      code: `throw new Error("token " + ${JSON.stringify(JWT)});`,
    });
    expect(out.__evalError).toBe(true);
    expect(out.message).toContain(JWT);
  });

  test("the pageEvalEnabled kill switch still refuses before running code", async () => {
    mockSettings({ pageEvalEnabled: false, confirmPageEval: false });
    await expect(runEval({ code: "return 1;" })).rejects.toThrow("page_eval disabled");
  });
});
