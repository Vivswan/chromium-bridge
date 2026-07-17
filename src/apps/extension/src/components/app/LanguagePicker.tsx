import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useI18n } from "@/hooks/useI18n";
import type { UiLanguage } from "@/lib/i18n";

const OPTIONS: UiLanguage[] = ["auto", "en", "zh_CN", "zh_TW"];

// Display-language chooser. Writing uiLanguage triggers storage.onChanged,
// which the i18n runtime watches and swaps the locale reactively (every open
// view re-renders via useI18n).
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
              {t(`lang.${opt}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
