import { describe, expect, test } from "vitest";
import { decide, type PolicyConfirmation, type RefusalCause } from "@/lib/background/policy";

describe("policy.decide", () => {
  test("a low-risk enabled tool is allowed with no confirmation", () => {
    const d = decide("tab_list", { disabledTools: [] });
    expect(d.allowed).toBe(true);
    expect(d.risk).toBe("low");
    expect(d.confirmation).toEqual({ required: false });
  });

  test("a disabled tool is refused with the typed cause", () => {
    const d = decide("tab_list", { disabledTools: ["tab_list"] });
    // still reports the tool's real risk shape for UI purposes
    expect(d).toMatchObject({
      allowed: false,
      cause: "disabled-in-settings",
      risk: "low",
      reason: "tool disabled in settings",
    });
  });

  test("page_eval requires confirmation (every-call, extension-ui)", () => {
    const d = decide("page_eval", { disabledTools: [] });
    expect(d.allowed).toBe(true);
    expect(d.risk).toBe("critical");
    expect(d.confirmation).toEqual({ required: true, channel: "extension-ui" });
  });

  test("tab_close confirms via the extension surface (every-call)", () => {
    const d = decide("tab_close", { disabledTools: [] });
    expect(d.allowed).toBe(true);
    expect(d.confirmation).toEqual({ required: true, channel: "extension-ui" });
  });

  test("an unknown op fails closed", () => {
    const d = decide("does_not_exist", { disabledTools: [] });
    expect(d).toMatchObject({
      allowed: false,
      cause: "unknown-tool",
      risk: "critical",
      reason: "unknown tool",
    });
  });

  test("a disabled tool that would otherwise need confirmation still reports it", () => {
    const d = decide("page_eval", { disabledTools: ["page_eval"] });
    expect(d).toMatchObject({ allowed: false, cause: "disabled-in-settings" });
    expect(d.confirmation).toEqual({ required: true, channel: "extension-ui" });
  });

  test("the cause union is closed and the confirmation pair cannot contradict", () => {
    const cause = (c: RefusalCause): RefusalCause => c;
    const confirmation = (c: PolicyConfirmation): PolicyConfirmation => c;
    expect(cause("disabled-in-settings")).toBe("disabled-in-settings");
    // @ts-expect-error - a cause outside the closed union must not compile;
    // the disable gate switches on it exhaustively
    cause("tool disabled in settings");
    // @ts-expect-error - "required" without a channel is unrepresentable
    confirmation({ required: true });
    // @ts-expect-error - "required over no channel" is unrepresentable
    confirmation({ required: true, channel: "none" });
  });
});
