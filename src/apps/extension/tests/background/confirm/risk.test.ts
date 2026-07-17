import { describe, expect, test } from "vitest";
import { describeAction, describeTarget, isHighRiskClick } from "@/lib/background/confirm/risk";
import type { ClickProbe } from "@/lib/dom/page-api";

function target(over: Partial<ClickProbe>): ClickProbe {
  return { tagName: "DIV", role: "", type: "", hasHref: false, name: "", ...over };
}

describe("isHighRiskClick", () => {
  test("submit buttons are high-risk", () => {
    expect(isHighRiskClick(target({ tagName: "BUTTON", role: "button", type: "submit" }))).toBe(
      true,
    );
  });

  test("non-submit buttons are not high-risk", () => {
    expect(isHighRiskClick(target({ tagName: "BUTTON", role: "button", type: "button" }))).toBe(
      false,
    );
    expect(isHighRiskClick(target({ tagName: "BUTTON", role: "button", type: "" }))).toBe(false);
  });

  test("anchors with href and link roles are high-risk", () => {
    expect(isHighRiskClick(target({ tagName: "A", hasHref: true }))).toBe(true);
    expect(isHighRiskClick(target({ role: "link" }))).toBe(true);
  });

  test("anchors without href and plain elements are not", () => {
    expect(isHighRiskClick(target({ tagName: "A", hasHref: false }))).toBe(false);
    expect(isHighRiskClick(target({ tagName: "SPAN" }))).toBe(false);
  });
});

describe("describeAction", () => {
  test("links describe as navigate, buttons as submit, others as click", () => {
    expect(describeAction(target({ role: "link" }), "click")).toBe("navigate");
    expect(describeAction(target({ tagName: "A" }), "click")).toBe("navigate");
    expect(describeAction(target({ role: "button" }), "click")).toBe("submit");
    expect(describeAction(target({}), "click")).toBe("click");
  });

  test("non-click kinds pass through", () => {
    expect(describeAction(target({}), "press")).toBe("press");
  });
});

describe("describeTarget", () => {
  test("prefers name, then role, then tag; truncates long names", () => {
    expect(describeTarget(target({ name: "Buy now" }))).toBe("Buy now");
    expect(describeTarget(target({ role: "button" }))).toBe("button");
    expect(describeTarget(target({ tagName: "SPAN" }))).toBe("span");
    expect(describeTarget(target({ name: "x".repeat(60) }))).toBe(`${"x".repeat(40)}...`);
  });
});
