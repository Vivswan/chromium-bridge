import { useI18n } from "@/hooks/useI18n";
import { cn } from "@/lib/cn";
import { getUiLanguage, type UiLanguage } from "@/lib/i18n";
import { chooseLanguage } from "@/lib/lang-sync";
import { NATIVE_LANGUAGE_NAMES } from "@/lib/native-language-names";

const OPTIONS: UiLanguage[] = ["auto", "en", "zh_CN", "zh_TW"];

// Display-language chooser as the Control Tower segmented control: the
// buttons show the raw locale codes (mono, compact) as a toggle group, while
// the accessible names carry each language in its own language
// (NATIVE_LANGUAGE_NAMES) - never translated into the active locale; only
// "match system" is a translatable phrase.
//
// The click handler below is the ONE user gesture that records the choice
// host-side (lang-sync's chooseLanguage -> lang_set, ADR-0032 decision 7).
// The reverse path - applying an incoming lang_current - never runs through
// this component and never emits; see lib/lang-sync.ts.
export function LanguagePicker() {
  const { t } = useI18n();
  const value = getUiLanguage();

  return (
    <div className="flex items-center gap-2">
      <span id="lang-label" className="text-[11px] text-text-3">
        {t("lang.label")}
      </span>
      <div className="seg">
        {OPTIONS.map((opt) => (
          <button
            key={opt}
            type="button"
            aria-pressed={value === opt}
            aria-label={opt === "auto" ? t("lang.auto") : NATIVE_LANGUAGE_NAMES[opt]}
            className={cn("seg-btn", value === opt && "active")}
            onClick={() => chooseLanguage(opt)}
          >
            {opt}
          </button>
        ))}
      </div>
    </div>
  );
}
