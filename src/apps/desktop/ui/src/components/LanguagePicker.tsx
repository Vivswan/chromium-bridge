import { useI18n } from "@/hooks/useI18n";
import { cn } from "@/lib/cn";
import { getUiLanguage, setUiLanguage, type UiLanguage } from "@/lib/i18n";
import { NATIVE_LANGUAGE_NAMES } from "@/lib/native-language-names";

const OPTIONS: UiLanguage[] = ["auto", "en", "zh_CN", "zh_TW"];

// Display-language chooser as the Control Tower segmented control: the
// buttons show the raw locale codes (mono, compact) as a toggle group, while
// the accessible names carry each language in its own language
// (NATIVE_LANGUAGE_NAMES) - never translated into the active locale; only
// "match system" is a translatable phrase.
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
            onClick={() => setUiLanguage(opt)}
          >
            {opt}
          </button>
        ))}
      </div>
    </div>
  );
}
