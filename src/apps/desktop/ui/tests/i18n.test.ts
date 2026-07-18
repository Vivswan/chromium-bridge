import { describe, expect, it } from "vitest";
import { resolveUiLocale, t } from "../src/lib/i18n";
import { en } from "../src/locales/en";
import { zh_CN } from "../src/locales/zh_CN";
import { zh_TW } from "../src/locales/zh_TW";

// The Record<MessageKey, string> types already make coverage a compile
// error; these assertions are the runtime backstop (and the readable CI
// failure) should the typing ever be loosened.
describe("locale coverage", () => {
  const enKeys = Object.keys(en).sort();

  it("zh_CN mirrors en exactly", () => {
    expect(Object.keys(zh_CN).sort()).toEqual(enKeys);
  });

  it("zh_TW mirrors en exactly", () => {
    expect(Object.keys(zh_TW).sort()).toEqual(enKeys);
  });

  it("no bundle has an empty message", () => {
    for (const bundle of [en, zh_CN, zh_TW]) {
      for (const [key, value] of Object.entries(bundle)) {
        expect(value.trim(), key).not.toBe("");
      }
    }
  });
});

describe("resolveUiLocale", () => {
  it("honors an explicit choice", () => {
    expect(resolveUiLocale("zh_TW", "en-US")).toBe("zh_TW");
    expect(resolveUiLocale("en", "zh-CN")).toBe("en");
  });

  it("maps system tags in auto mode (bare zh means Simplified)", () => {
    expect(resolveUiLocale("auto", "zh")).toBe("zh_CN");
    expect(resolveUiLocale("auto", "zh-CN")).toBe("zh_CN");
    expect(resolveUiLocale("auto", "zh-Hans-CN")).toBe("zh_CN");
    expect(resolveUiLocale("auto", "zh-TW")).toBe("zh_TW");
    expect(resolveUiLocale("auto", "zh-Hant")).toBe("zh_TW");
    expect(resolveUiLocale("auto", "zh-HK")).toBe("zh_TW");
    expect(resolveUiLocale("auto", "en-US")).toBe("en");
    expect(resolveUiLocale("auto", "de-DE")).toBe("en");
  });
});

describe("t", () => {
  it("substitutes positional parameters", () => {
    expect(t("overview.browsers_summary", ["1", "2"])).toContain("1");
    expect(t("overview.browsers_summary", ["1", "2"])).toContain("2");
  });

  it("leaves an unsupplied placeholder visible rather than dropping it", () => {
    expect(t("overview.browsers_summary", ["1"])).toContain("$2");
  });
});
