// The runtime i18n: BCP-47 resolution, the seq-guarded async swap, and the
// English fallback. fetch is stubbed per locale so no _locales build is needed.

import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing";

const EN = {
  options_title: { message: "Settings" },
  confirm_countdown: { message: "Denies in $1s" },
};
const ZH_CN = { options_title: { message: "设置" }, confirm_countdown: { message: "$1 秒后拒绝" } };

function stubFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const body = url.includes("/zh_CN/") ? ZH_CN : EN;
      return { ok: true, json: async () => body } as Response;
    }),
  );
}

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  stubFetch();
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("resolveUiLocale", () => {
  test("explicit choice wins over the browser language", async () => {
    const { resolveUiLocale } = await import("@/lib/i18n");
    expect(resolveUiLocale("en", "zh-CN")).toBe("en");
    expect(resolveUiLocale("zh_TW", "en-US")).toBe("zh_TW");
  });

  test("auto maps zh variants per Chrome convention", async () => {
    const { resolveUiLocale } = await import("@/lib/i18n");
    expect(resolveUiLocale("auto", "zh")).toBe("zh_CN");
    expect(resolveUiLocale("auto", "zh-CN")).toBe("zh_CN");
    expect(resolveUiLocale("auto", "zh-SG")).toBe("zh_CN");
    expect(resolveUiLocale("auto", "zh-TW")).toBe("zh_TW");
    expect(resolveUiLocale("auto", "zh-Hant-HK")).toBe("zh_TW");
    expect(resolveUiLocale("auto", "zh-MO")).toBe("zh_TW");
    expect(resolveUiLocale("auto", "ja")).toBe("en");
    expect(resolveUiLocale("auto", "en-US")).toBe("en");
  });
});

describe("native language names", () => {
  // The picker shows every language in that language itself, always - the
  // escape hatch for a user stuck in a UI they cannot read. These values must
  // never be translated or moved into the locale bundles.
  test("each language names itself, untranslated", async () => {
    const { NATIVE_LANGUAGE_NAMES } = await import("@/lib/native-language-names");
    expect(NATIVE_LANGUAGE_NAMES).toEqual({
      en: "English",
      zh_CN: "简体中文",
      zh_TW: "繁體中文",
    });
  });
});

describe("t + initI18n", () => {
  test("resolves the chosen locale, falling back to English per key", async () => {
    await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
    const { initI18n, t, getActiveLocale } = await import("@/lib/i18n");
    await initI18n();
    expect(getActiveLocale()).toBe("zh_CN");
    expect(t("options.title")).toBe("设置");
    // Substitution positions are preserved through translation.
    expect(t("confirm.countdown", ["30"])).toBe("30 秒后拒绝");
  });

  test("an unknown key returns the key itself", async () => {
    const { initI18n, t } = await import("@/lib/i18n");
    await initI18n();
    expect(t("nope.not_a_key" as never)).toBe("nope.not_a_key");
  });

  test("swaps locale reactively when uiLanguage changes", async () => {
    const { initI18n, t, subscribeLocale, getLocaleVersion } = await import("@/lib/i18n");
    await initI18n();
    expect(t("options.title")).toBe("Settings");
    let bumped = 0;
    subscribeLocale(() => {
      bumped += 1;
    });
    await fakeBrowser.storage.local.set({ uiLanguage: "zh_CN" });
    // storage.onChanged is synchronous in fakeBrowser; give the async refresh a tick.
    await new Promise((r) => setTimeout(r, 0));
    expect(getLocaleVersion()).toBeGreaterThan(0);
    expect(bumped).toBeGreaterThan(0);
    expect(t("options.title")).toBe("设置");
  });
});
