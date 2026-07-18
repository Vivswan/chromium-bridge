import type * as React from "react";
import { useI18n } from "@/hooks/useI18n";
import { cn } from "@/lib/cn";

/* The Control Tower primitive set. Every class name here is defined in
   styles.css, ported from design-explorations/control-tower/theme.css. */

/** A bordered surface; `hero` marks the screen's one centerpiece (raised
 * edge, larger radius), `flush` makes it a table-card (content to edges). */
export function Card({
  hero,
  flush,
  children,
  className,
  ...props
}: React.HTMLAttributes<HTMLElement> & { hero?: boolean; flush?: boolean }) {
  return (
    <section
      className={cn("card", flush === true && "table-card", hero === true && "hero", className)}
      {...props}
    >
      {children}
    </section>
  );
}

export type Tone = "live" | "pending" | "down" | "idle";

/** The bare 7px signal dot. */
export function Dot({ tone = "idle", className }: { tone?: Tone; className?: string }) {
  return (
    <span
      aria-hidden
      className={cn("status-dot", tone !== "idle" && tone, className)}
      data-tone={tone}
    />
  );
}

/** Inline signal dot + label. */
export function StatusDot({
  tone,
  children,
  className,
}: {
  tone: Tone;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-[7px] text-[13px] font-medium", className)}>
      <Dot tone={tone} />
      {children}
    </span>
  );
}

/** Uppercase mono status capsule - status only, never a label. */
export function Pill({
  tone = "idle",
  dot = false,
  children,
  className,
}: {
  tone?: Tone | "danger";
  dot?: boolean;
  children: React.ReactNode;
  className?: string;
}) {
  const toneClass = {
    live: "pill-live",
    pending: "pill-pending",
    down: "pill-danger",
    danger: "pill-danger",
    idle: "",
  }[tone];
  return (
    <span className={cn("pill", toneClass, className)}>
      {dot && <Dot tone={tone === "danger" ? "down" : tone} />}
      {children}
    </span>
  );
}

/** Identity material chip: fingerprints, host ids, origins. Always mono.
 * `wrap` lets long identity material wrap - it must never truncate. */
export function ChipMono({
  wrap,
  children,
  className,
}: {
  wrap?: boolean;
  children: React.ReactNode;
  className?: string;
}) {
  return <span className={cn("chip-mono", wrap === true && "wrap", className)}>{children}</span>;
}

/** The fingerprint glyph from the mockups (a Touch ID mark). */
export function TouchIdIcon({ size = 10 }: { size?: number }) {
  return (
    <svg
      width={size * 0.9}
      height={size}
      viewBox="0 0 12 14"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M6 3.5c2.5 0 4 1.8 4 4.2 0 2-.4 3.6-1 4.8M6 6c1.3 0 2 .9 2 2.1 0 1.6-.3 2.9-.8 3.9M6 8.6c0 1.6-.4 2.9-1.1 3.9M3 5.2C2.3 6 2 7 2 8c0 1.3-.2 2.4-.6 3.3"
        stroke="currentColor"
        strokeWidth="1.1"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** The "this asks for Touch ID" mark, placed next to gated controls. */
export function TouchIdChip({ className }: { className?: string }) {
  const { t } = useI18n();
  return (
    <ChipMono className={className}>
      <TouchIdIcon />
      {t("auth.touch_id")}
    </ChipMono>
  );
}

/** The disclosure/expand chevron; rotates via the .twist CSS. */
export function Twist({ size = 9 }: { size?: number }) {
  return (
    <svg
      className="twist"
      width={size}
      height={size}
      viewBox="0 0 10 10"
      fill="none"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M3 1.5 6.5 5 3 8.5"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** One-line plain-language consequence under a control. Neutral ink on
 * purpose: amber stays reserved for pending states. */
export function Consequence({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <p className={cn("consequence", className)}>{children}</p>;
}

/** Uppercase mono section label. */
export function SpecLabel({
  children,
  className,
  as: Tag = "span",
}: {
  children: React.ReactNode;
  className?: string;
  as?: "span" | "h2";
}) {
  return <Tag className={cn("spec-label", className)}>{children}</Tag>;
}

/** Monospace block for command snippets, fingerprints, transcripts. */
export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <pre
      className={cn(
        "mono m-0 overflow-x-auto whitespace-pre-wrap break-all rounded-md border " +
          "border-edge bg-surface-1 px-3 py-2 text-[11px] leading-relaxed text-text-2",
        className,
      )}
    >
      {children}
    </pre>
  );
}

/** Error strip for surfaced Rust errors (shown verbatim). */
export function ErrorNote({ children }: { children: React.ReactNode }) {
  if (children === undefined || children === null || children === "") return null;
  return (
    <div role="alert" className="banner banner-danger">
      <span className="banner-text mono text-[11px]">{children}</span>
    </div>
  );
}

export function Field({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
    </div>
  );
}

export function TextInput({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn("text-input", className)} />;
}

/** Per-view frame: title/sub + optional right-side status, a body, and the
 * pinned mono footer. Views that scroll internally (Audit's ledger,
 * Security's policy scroll) pass scroll={false} and manage it themselves. */
export function ViewShell({
  title,
  sub,
  right,
  foot,
  scroll = true,
  children,
}: {
  title: string;
  sub?: string;
  right?: React.ReactNode;
  foot?: React.ReactNode;
  scroll?: boolean;
  children: React.ReactNode;
}) {
  return (
    <>
      <div className="main-head">
        <div>
          <h1 className="main-title">{title}</h1>
          {sub !== undefined && <p className="main-sub">{sub}</p>}
        </div>
        {right}
      </div>
      {scroll ? (
        <div className="-mx-2 min-h-0 flex-1 overflow-y-auto px-2">{children}</div>
      ) : (
        children
      )}
      {foot !== undefined && <footer className="main-foot">{foot}</footer>}
    </>
  );
}
