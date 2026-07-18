import type { UiLocale } from "@/lib/i18n";

// Each language's name in that language itself, shown as-is in the language
// picker regardless of the active locale - the convention users rely on to
// find their way back from a UI they cannot read. Deliberately outside the
// locale bundles (never translated); this file and the locale bundles are
// the only desktop-UI sources allowlisted by the check-cjk gate.
export const NATIVE_LANGUAGE_NAMES: Readonly<Record<UiLocale, string>> = {
  en: "English",
  zh_CN: "简体中文",
  zh_TW: "繁體中文",
};
