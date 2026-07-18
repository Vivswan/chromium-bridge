import type * as React from "react";
import { cn } from "@/lib/cn";

/** A titled panel; the app's one container primitive. */
export function Card({
  title,
  children,
  className,
}: {
  title?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("rounded-xl border border-edge bg-surface p-4", className)}>
      {title !== undefined && <h2 className="mb-3 text-sm font-semibold text-body">{title}</h2>}
      {children}
    </section>
  );
}

/** Inline status dot + label. */
export function StatusDot({
  tone,
  children,
}: {
  tone: "ok" | "warn" | "bad" | "muted";
  children: React.ReactNode;
}) {
  const toneClass = {
    ok: "bg-brand",
    warn: "bg-pending",
    bad: "bg-danger",
    muted: "bg-faint",
  }[tone];
  return (
    <span className="inline-flex items-center gap-2 text-sm text-body">
      <span aria-hidden className={cn("size-2 shrink-0 rounded-full", toneClass)} />
      {children}
    </span>
  );
}

/** Monospace block for command snippets, fingerprints, transcripts. */
export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <pre
      className={cn(
        "overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-edge-soft " +
          "bg-edge-soft px-3 py-2 font-mono text-xs text-body",
        className,
      )}
    >
      {children}
    </pre>
  );
}

/** Error callout for surfaced Rust errors (shown verbatim). */
export function ErrorNote({ children }: { children: React.ReactNode }) {
  if (children === undefined || children === null || children === "") return null;
  return (
    <div
      role="alert"
      className="rounded-lg border border-danger bg-danger-surface px-3 py-2 text-xs text-body"
    >
      {children}
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
    <label className="flex flex-col gap-1 text-sm text-body" htmlFor={htmlFor}>
      <span className="text-xs font-medium text-muted">{label}</span>
      {children}
    </label>
  );
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "h-9 rounded-lg border border-edge bg-surface px-3 text-sm text-body " +
          "placeholder:text-faint focus-visible:outline-2 focus-visible:outline-offset-1 " +
          "focus-visible:outline-brand",
        props.className,
      )}
    />
  );
}
