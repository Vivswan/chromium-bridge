import { useSyncExternalStore } from "react";
import { getLocaleVersion, subscribeLocale, t } from "@/lib/i18n";

/** Subscribe a component to locale changes so `t()` re-renders on a language
 * switch. Returns the same `t`; reading localeVersion forces the re-render. */
export function useI18n(): { t: typeof t; localeVersion: number } {
  const localeVersion = useSyncExternalStore(subscribeLocale, getLocaleVersion, getLocaleVersion);
  return { t, localeVersion };
}
