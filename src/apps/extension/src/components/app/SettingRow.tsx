import type { ReactNode } from "react";
import { Switch } from "@/components/ui/switch";

// A Control Tower setting row: flat and open (no card chrome), hairline
// separated, title + one-line description, and one plain-language consequence
// line shown while the toggle sits in its dangerous position. `dangerOn`
// picks which side is risky (protections warn when OFF; opt-in powers warn
// when ON). Consequence ink is neutral on purpose - amber stays reserved for
// pending states.
export function SettingRow({
  title,
  desc,
  warn,
  checked,
  dangerOn,
  onChange,
}: {
  title: string;
  desc: string;
  warn?: string;
  checked: boolean;
  dangerOn: "checked" | "unchecked";
  onChange: (v: boolean) => void;
}) {
  const dangerous = dangerOn === "checked" ? checked : !checked;
  const showWarn = warn !== undefined && dangerous;
  return (
    <div className="flex items-start gap-3.5 border-b border-edge py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-medium">{title}</div>
        <div className="mt-0.5 text-xs text-text-3">{desc}</div>
        {showWarn && <p className="consequence mt-1">{warn}</p>}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} aria-label={title} className="mt-0.5" />
    </div>
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="section-title mb-2">{title}</h2>
      {children}
    </section>
  );
}
