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
    <div className="py-1">
      {(entries?.length ?? 0) === 0 && (
        <div className="text-xs text-text-3">{t("audit.empty")}</div>
      )}
      {entries && entries.length > 0 && (
        <ul className="m-0 max-h-80 list-none overflow-y-auto p-0">
          {[...entries].reverse().map((e) => (
            <li
              key={`${e.at}-${e.kind}-${e.name ?? ""}`}
              className="flex items-baseline gap-3 py-1 font-mono text-[11px] leading-relaxed"
            >
              <span className="tnum shrink-0 text-text-3">{new Date(e.at).toLocaleString()}</span>
              <span className="min-w-0">
                <span className="text-xs font-medium text-text-1">{kindLabel(e.kind)}</span>
                {(e.tool || e.name || e.outcome || e.detail) && (
                  <span className="ml-2 break-all text-text-3">
                    {[e.tool, e.name, e.outcome, e.detail].filter(Boolean).join(" - ")}
                  </span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="consequence mt-2">{t("audit.desc")}</p>
    </div>
  );
}
