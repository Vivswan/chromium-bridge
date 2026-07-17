import type { UiLocale } from "@/lib/i18n";

// Each language's name in that language itself, shown as-is in the language
// picker regardless of the active locale - the convention users rely on to
// find their way back from a UI they cannot read. These strings deliberately
// live outside the locale bundles (they must never be translated) and this
// file is the one allowlisted source of CJK outside src/locales; the
// check-cjk gate rejects CJK anywhere else.
export const NATIVE_LANGUAGE_NAMES: Readonly<Record<UiLocale, string>> = {
  en: "English",
  zh_CN: "简体中文",
  zh_TW: "繁體中文",
};
