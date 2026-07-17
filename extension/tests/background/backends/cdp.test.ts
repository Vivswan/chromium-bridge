// evalResponseToPayload normalizes a raw Runtime.evaluate response into the
// page_eval result shape. Masking of both paths (value and exception) happens
// downstream in egress.ts - see tests/background/egress.test.ts.

import { describe, expect, test } from "vitest";
import { evalResponseToPayload } from "@/lib/background/backends/cdp";

describe("evalResponseToPayload", () => {
  test("an exception becomes structured __evalError data", () => {
    const out = evalResponseToPayload({
      exceptionDetails: {
        text: "Uncaught",
        exception: {
          className: "TypeError",
          description: "TypeError: boom\n    at <anonymous>:1:7",
        },
      },
    }) as { __evalError: boolean; name: string; message: string; stack: string };
    expect(out.__evalError).toBe(true);
    expect(out.name).toBe("TypeError");
    expect(out.message).toBe("TypeError: boom");
    expect(out.stack).toContain("at <anonymous>");
  });

  test("exceptionDetails.text is the fallback description", () => {
    const out = evalResponseToPayload({ exceptionDetails: { text: "boom" } }) as {
      __evalError: boolean;
      message: string;
    };
    expect(out.__evalError).toBe(true);
    expect(out.message).toBe("boom");
  });

  test("a success value passes through as-is", () => {
    expect(evalResponseToPayload({ result: { value: { a: 1 } } })).toEqual({ a: 1 });
  });

  test("very long exception descriptions are truncated in the stack", () => {
    const out = evalResponseToPayload({
      exceptionDetails: { text: `x${"y".repeat(3000)}` },
    }) as { stack: string };
    expect(out.stack.length).toBeLessThanOrEqual(2003);
  });

  test("an empty response resolves to undefined", () => {
    expect(evalResponseToPayload({})).toBeUndefined();
  });
});
