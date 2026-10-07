import type { AuditEntry } from "@chromium-bridge/shared/enclave";
import type { AuditTrailEntry } from "@chromium-bridge/shared/generated/envelope";
import type { RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";

// The read-only audit panel: two lists, newest first. This browser's own ring of security decisions
// (confirmations, pairing approvals, revocations, kill toggles) lives in the extension-context-only trusted
// storage and refreshes on storage.onChanged, so a new decision appears without polling. The host's durable
// trail is the page `chromium-bridge audit` prints, read through the host on demand (mount and Refresh); the
// host spells each line's words, so the two surfaces cannot disagree. Strictly display.
export function AuditPanel() {
  const { t } = useI18n();
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [host, setHost] = useState<RuntimeResponse<"get_host_audit"> | null>(null);
  const [hostBusy, setHostBusy] = useState(false);

  const refresh = useCallback(async () => {
    const r = await send({ type: "get_audit" });
    setEntries(r.ok ? r.entries : null);
  }, []);

  const refreshHost = useCallback(async () => {
    setHostBusy(true);
    setHost(await send({ type: "get_host_audit" }));
    setHostBusy(false);
  }, []);

  useEffect(() => {
    void refresh();
    void refreshHost();
    const onChanged = (changes: Record<string, unknown>, area: string) => {
      if (area === "local" && "auditRing" in changes) void refresh();
    };
    browser.storage.onChanged.addListener(onChanged);
    return () => browser.storage.onChanged.removeListener(onChanged);
  }, [refresh, refreshHost]);

  const kindLabel = (kind: AuditEntry["kind"]) =>
    t(`audit.kind_${kind}` as Parameters<typeof t>[0]);

  return (
    <div className="py-1">
      <p className="consequence m-0">{t("audit.desc")}</p>

      <div className="section-title mt-3 mb-1.5">{t("audit.browser_title")}</div>
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

      <div className="mt-5 flex items-start justify-between gap-3">
        <div className="section-title mb-1.5">{t("audit.host_title")}</div>
        <Button variant="ghost" onClick={() => void refreshHost()} disabled={hostBusy}>
          {t("audit.refresh")}
        </Button>
      </div>
      {host === null && <div className="text-xs text-text-3">{t("audit.host_loading")}</div>}
      {/* An unreadable trail is unknown, not a denial: pending ink, the host's own words. */}
      {host && !host.ok && (
        <div role="status" className="text-xs font-semibold text-pending">
          {t("audit.host_error", [host.error])}
        </div>
      )}
      {host?.ok && host.entries.length === 0 && host.older === 0 && (
        <div className="text-xs text-text-3">{t("audit.host_empty", [host.path])}</div>
      )}
      {host?.ok && host.entries.length > 0 && (
        <ul className="m-0 max-h-80 list-none overflow-y-auto p-0">
          {host.entries.map((entry, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: the page is replaced whole on every read and never reordered, so a line's position is its identity (two records can share every field)
            <HostTrailLine key={index} entry={entry} />
          ))}
        </ul>
      )}
      <p className="consequence mt-2">{t("audit.host_desc")}</p>
    </div>
  );
}

// A JS-safe integer can still lie past the range Date represents (about 8.64e15 ms either side of the
// epoch); such a timestamp shows raw rather than as "Invalid Date".
function localTime(epochMs: number): string {
  const date = new Date(epochMs);
  return Number.isNaN(date.getTime()) ? String(epochMs) : date.toLocaleString();
}

// One line of the host trail, the CLI line's three parts: the timestamp localized here, the kind and its
// fields as the host spelled them. An unparsable line keeps its position with the host's stand-in text.
function HostTrailLine({ entry }: { entry: AuditTrailEntry }) {
  if (entry.entry === "unrecognized") {
    return (
      <li className="py-1 font-mono text-[11px] font-semibold leading-relaxed text-danger">
        {entry.text}
      </li>
    );
  }
  return (
    <li className="flex items-baseline gap-3 py-1 font-mono text-[11px] leading-relaxed">
      <span className="tnum shrink-0 text-text-3">{localTime(entry.ts_ms)}</span>
      <span className="min-w-0">
        <span className="text-xs font-medium text-text-1">{entry.kind}</span>
        {entry.fields && <span className="ml-2 break-all text-text-3">{entry.fields}</span>}
      </span>
    </li>
  );
}
