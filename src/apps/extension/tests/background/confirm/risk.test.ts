import { describe, expect, test } from "vitest";
import { describeAction, describeTarget, isHighRiskClick } from "@/lib/background/confirm/risk";
import type { ClickProbe } from "@/lib/dom/page-api";

function target(over: Partial<ClickProbe>): ClickProbe {
  return { tagName: "DIV", role: "", type: "", hasHref: false, name: "", ...over };
}

describe("isHighRiskClick", () => {
  test.each([
    ["a submit button", { tagName: "BUTTON", role: "button", type: "submit" }, true],
    ["a type=button button", { tagName: "BUTTON", role: "button", type: "button" }, false],
    ["a typeless button", { tagName: "BUTTON", role: "button", type: "" }, false],
    ["an anchor with href", { tagName: "A", hasHref: true }, true],
    ["a link role", { role: "link" }, true],
    ["an anchor without href", { tagName: "A", hasHref: false }, false],
    ["a plain span", { tagName: "SPAN" }, false],
  ] satisfies Array<[string, Partial<ClickProbe>, boolean]>)("%s", (_case, over, expected) => {
    expect(isHighRiskClick(target(over))).toBe(expected);
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
