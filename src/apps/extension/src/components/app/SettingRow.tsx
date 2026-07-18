import type { ReactNode } from "react";
import { useId } from "react";
import { Switch } from "@/components/ui/switch";
import { useI18n } from "@/hooks/useI18n";

// A Control Tower setting row: flat and open (no card chrome), hairline
// separated, title + one-line description, and one plain-language consequence
// line shown while the toggle sits in its dangerous position. `dangerOn`
// picks which side is risky (protections warn when OFF; opt-in powers warn
// when ON). Consequence ink is neutral on purpose - amber stays reserved for
// pending states. `more` holds provenance/platform detail (ADR references,
// caveats) behind a details affordance so the visible copy stays one line.
// The title is a <label> bound to the switch: the text is part of the hit
// target, compensating the small control.
export function SettingRow({
  title,
  desc,
  warn,
  more,
  checked,
  dangerOn,
  onChange,
}: {
  title: string;
  desc: string;
  warn?: string;
  more?: string;
  checked: boolean;
  dangerOn: "checked" | "unchecked";
  onChange: (v: boolean) => void;
}) {
  const { t } = useI18n();
  const id = useId();
  const dangerous = dangerOn === "checked" ? checked : !checked;
  const showWarn = warn !== undefined && dangerous;
  return (
    <div className="flex items-start gap-3.5 border-b border-edge py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <label htmlFor={id} className="block cursor-pointer text-[13px] font-medium">
          {title}
        </label>
        <div className="mt-0.5 text-xs text-text-3">{desc}</div>
        {showWarn && <p className="consequence mt-1">{warn}</p>}
        {more && (
          <details className="mt-0.5">
            <summary
              className="cursor-pointer text-[11px] text-text-3"
              aria-label={`${title}: ${t("settings.more_label")}`}
            >
              {t("settings.more_label")}
            </summary>
            <p className="m-0 mt-0.5 text-[11px] text-text-3">{more}</p>
          </details>
        )}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} className="mt-0.5" />
    </div>
  );
}

export function Section({
  title,
  id,
  children,
}: {
  title: string;
  id?: string;
  children: ReactNode;
}) {
  return (
    <section className="mt-8" id={id}>
      <h2 className="section-title mb-2">{title}</h2>
      {children}
    </section>
  );
}
