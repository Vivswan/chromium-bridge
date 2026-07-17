import { describe, expect, test } from "vitest";
import { evalResponseToPayload } from "@/lib/background/backends/cdp";

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpM";

describe("evalResponseToPayload", () => {
  test("an exception carrying a secret egresses masked", () => {
    const out: any = evalResponseToPayload(
      {
        exceptionDetails: {
          text: "Uncaught",
          exception: { className: "Error", description: `Error: ${JWT}\n    at <anonymous>:1:7` },
        },
      } as any,
      true,
    );
    expect(out.__evalError).toBe(true);
    expect(out.name).toBe("Error");
    expect(out.message).not.toContain(JWT);
    expect(out.message).toContain("••••");
    expect(out.stack).not.toContain(JWT);
  });

  test("exceptionDetails.text is the fallback and is masked too", () => {
    const out: any = evalResponseToPayload(
      { exceptionDetails: { text: `boom ${JWT}` } } as any,
      true,
    );
    expect(out.__evalError).toBe(true);
    expect(out.message).not.toContain(JWT);
  });

  test("success values pass the same gate", () => {
    const out: any = evalResponseToPayload(
      { result: { value: { jwt: JWT, note: "hi" } } } as any,
      true,
    );
    expect(JSON.stringify(out)).not.toContain(JWT);
    expect(out.note).toBe("hi");
  });

  test("mask=false (explicit opt-out) leaves both paths raw", () => {
    const err: any = evalResponseToPayload(
      { exceptionDetails: { text: `boom ${JWT}` } } as any,
      false,
    );
    expect(err.message).toContain(JWT);
    const ok: any = evalResponseToPayload({ result: { value: JWT } } as any, false);
    expect(ok).toBe(JWT);
  });

  test("an empty response resolves to undefined", () => {
    expect(evalResponseToPayload({} as any, true)).toBeUndefined();
  });
});
