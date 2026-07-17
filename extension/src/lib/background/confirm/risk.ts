// Pure click-risk helpers, THE single copy (previously triplicated across
// content/actions.ts, content/toast.ts, and cdp/click-risk.ts). They operate
// on the ClickProbe descriptor the shared page API returns, so both backends
// classify identically and neither owns the DOM.

import type { ClickProbe } from "../../dom/page-api";

/** Submit buttons and navigating links are gated (ADR-0006's tiering). */
export function isHighRiskClick(t: ClickProbe): boolean {
  if (t.role === "button" && t.type === "submit") return true;
  if (t.tagName === "A" && t.hasHref) return true;
  if (t.role === "link") return true;
  return false;
}

export function describeAction(t: ClickProbe, kind: string): string {
  if (kind === "click") {
    if (t.role === "link" || t.tagName === "A") return "navigate";
    if (t.role === "button") return "submit";
    return "click";
  }
  return kind;
}

export function describeTarget(t: ClickProbe): string {
  const s = t.name || t.role || t.tagName.toLowerCase();
  return s.length > 40 ? `${s.slice(0, 40)}...` : s;
}
