import type { ReactNode } from "react";
import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/cn";

// A toggle card: title + description, an optional warning line shown when the
// toggle is in its dangerous position, and danger styling to match. `dangerOn`
// picks which side is risky (protections warn when OFF; opt-in powers warn
// when ON).
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
    <div
      className={cn(
        "mb-2.5 flex items-start gap-3 rounded-xl border p-3.5",
        dangerous && warn ? "border-warn-edge bg-warn-surface" : "border-edge bg-surface",
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="font-semibold">{title}</div>
        <div className="mt-0.5 text-[12.5px] text-muted">{desc}</div>
        {showWarn && <div className="mt-1.5 text-xs font-semibold text-danger">{warn}</div>}
      </div>
      <Switch checked={checked} onCheckedChange={onChange} aria-label={title} />
    </div>
  );
}

export function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2 className="mt-8 mb-3 text-xs font-bold uppercase tracking-wider text-muted">{title}</h2>
      {children}
    </section>
  );
}
