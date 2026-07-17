import { describe, expect, test } from "bun:test";
import { parseCombo } from "./actions";

describe("parseCombo", () => {
  test("a single named key has no modifiers", () => {
    expect(parseCombo("Enter")).toEqual({
      key: "Enter",
      code: "Enter",
      ctrlKey: false,
      shiftKey: false,
      altKey: false,
      metaKey: false,
    });
  });

  test("a single letter maps to a KeyX code", () => {
    expect(parseCombo("a").code).toBe("KeyA");
    expect(parseCombo("Z").code).toBe("KeyZ");
    expect(parseCombo("7").code).toBe("Digit7");
  });

  test("modifiers are parsed and the last token is the key", () => {
    const c = parseCombo("Control+A");
    expect(c.key).toBe("A");
    expect(c.ctrlKey).toBe(true);
    expect(c.shiftKey).toBe(false);
  });

  test("modifier aliases (ctrl / cmd / option) are recognized", () => {
    expect(parseCombo("ctrl+c").ctrlKey).toBe(true);
    expect(parseCombo("cmd+k").metaKey).toBe(true);
    expect(parseCombo("option+f").altKey).toBe(true);
    const multi = parseCombo("Control+Shift+Alt+Meta+K");
    expect([multi.ctrlKey, multi.shiftKey, multi.altKey, multi.metaKey]).toEqual([
      true,
      true,
      true,
      true,
    ]);
  });

  test("an unknown named key gets an empty code (still dispatchable by key)", () => {
    expect(parseCombo("F13").code).toBe("");
    expect(parseCombo("F13").key).toBe("F13");
  });
});
