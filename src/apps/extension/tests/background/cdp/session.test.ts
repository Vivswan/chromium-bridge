import { describe, expect, test } from "vitest";
import {
  buildEvaluateExpression,
  evalExceptionMessage,
  isDebuggable,
} from "@/lib/background/cdp/session";

describe("isDebuggable", () => {
  // Chrome rejects chrome.debugger.attach on these targets after the fact, so the refusal has to come first.
  test.each([
    ["https://www.bing.com/", true],
    ["http://localhost:3000/app", true],
    ["chrome://settings", false],
    ["chrome-extension://abc/options.html", false],
    ["https://chrome.google.com/webstore/detail/x", false],
    ["view-source:https://example.com", false],
    ["about:blank", false],
    ["edge://flags", false],
    [undefined, false],
    ["", false],
  ])("%s -> %s", (url, debuggable) => {
    expect(isDebuggable(url)).toBe(debuggable);
  });
});

describe("buildEvaluateExpression", () => {
  test("stringifies the function and applies it to JSON args", () => {
    function greet(name: string) {
      return `hi ${name}`;
    }
    const expr = buildEvaluateExpression(greet as (...a: never[]) => unknown, ["bob"]);
    expect(expr).toContain("greet");
    expect(expr).toContain('.apply(undefined, ["bob"])');
    // The produced expression is itself valid JS that evaluates to the result.
    // biome-ignore lint/security/noGlobalEval: the test's whole point is executing the built expression
    expect(eval(expr)).toBe("hi bob");
  });

  test("defaults to an empty args array", () => {
    const expr = buildEvaluateExpression((() => 42) as (...a: never[]) => unknown);
    expect(expr).toContain(".apply(undefined, [])");
    // biome-ignore lint/security/noGlobalEval: the test's whole point is executing the built expression
    expect(eval(expr)).toBe(42);
  });
});

describe("evalExceptionMessage", () => {
  test("prefers the exception description's first line", () => {
    expect(
      evalExceptionMessage({
        text: "Uncaught",
        exception: { description: "ReferenceError: x is not defined\n    at <anonymous>" },
      }),
    ).toBe("ReferenceError: x is not defined");
  });

  test("falls back to text when there is no description", () => {
    expect(evalExceptionMessage({ text: "Uncaught SyntaxError" })).toBe("Uncaught SyntaxError");
  });

  test("has a final generic fallback", () => {
    expect(evalExceptionMessage({})).toBe("evaluation failed");
  });
});
