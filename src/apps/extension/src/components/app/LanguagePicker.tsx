import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useI18n } from "@/hooks/useI18n";
import type { UiLanguage } from "@/lib/i18n";
import { NATIVE_LANGUAGE_NAMES } from "@/lib/native-language-names";

const OPTIONS: UiLanguage[] = ["auto", "en", "zh_CN", "zh_TW"];

// Display-language chooser. Writing uiLanguage triggers storage.onChanged,
// which the i18n runtime watches and swaps the locale reactively (every open
// view re-renders via useI18n). Each language option is rendered in its own
// language (NATIVE_LANGUAGE_NAMES), never translated into the active locale;
// only the "match browser" option is a translatable phrase.
export function LanguagePicker({
  value,
  onChange,
}: {
  value: UiLanguage;
  onChange: (v: UiLanguage) => void;
}) {
  const { t } = useI18n();
  return (
    <div className="flex items-center gap-3 text-sm">
      <span id="lang-label" className="text-muted">
        {t("lang.label")}
      </span>
      <Select value={value} onValueChange={(v) => onChange(v as UiLanguage)}>
        <SelectTrigger
          className="min-w-40"
          aria-labelledby="lang-label"
          aria-label={t("lang.label")}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {OPTIONS.map((opt) => (
            <SelectItem key={opt} value={opt}>
              {opt === "auto" ? t("lang.auto") : NATIVE_LANGUAGE_NAMES[opt]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
