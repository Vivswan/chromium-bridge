import type { AuditEntry } from "@chromium-bridge/shared";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";

// The ADR-0030 read-only audit panel: the extension's local ring of security
// decisions (confirmations, pairing approvals, revocations, kill toggles),
// newest first. Strictly display: there is nothing to click but scroll. The
// ring lives in the SW-only trusted storage and is fetched through the router
// (extension-page senders only); storage.onChanged drives refreshes, so a new
// decision appears without polling. The durable, host-side trail is
// `chromium-bridge audit`.
export function AuditPanel() {
  const { t } = useI18n();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await send<{ entries: AuditEntry[] }>({ type: "get_audit" });
      setEntries(r?.entries ?? null);
    } catch (e) {
      console.warn("[bb] audit panel refresh failed", e);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const onChanged = (changes: Record<string, unknown>, area: string) => {
      if (area === "local" && "auditRing" in changes) void refresh();
    };
    browser.storage.onChanged.addListener(onChanged);
    return () => browser.storage.onChanged.removeListener(onChanged);
  }, [refresh]);

  const kindLabel = (kind: AuditEntry["kind"]) =>
    t(`audit.kind_${kind}` as Parameters<typeof t>[0]);

  return (
    <div className="rounded-xl border border-edge p-3.5">
      <div className="text-xs text-muted">{t("audit.desc")}</div>
      {(entries?.length ?? 0) === 0 && (
        <div className="mt-2 text-xs text-muted">{t("audit.empty")}</div>
      )}
      {entries && entries.length > 0 && (
        <ul className="mt-2 max-h-80 divide-y divide-edge-soft overflow-y-auto">
          {[...entries].reverse().map((e) => (
            <li
              key={`${e.at}-${e.kind}-${e.name ?? ""}`}
              className="flex items-baseline gap-3 py-1.5"
            >
              <span className="shrink-0 font-mono text-[11px] text-faint">
                {new Date(e.at).toLocaleString()}
              </span>
              <span className="min-w-0">
                <span className="text-[13px] font-medium">{kindLabel(e.kind)}</span>
                {(e.tool || e.name || e.outcome || e.detail) && (
                  <span className="ml-2 break-all text-[11px] text-muted">
                    {[e.tool, e.name, e.outcome, e.detail].filter(Boolean).join(" - ")}
                  </span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
