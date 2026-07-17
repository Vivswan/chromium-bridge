import { PendingAllowSchema } from "@chromium-bridge/shared";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import type { MessageKey } from "@/lib/i18n";
import { type EnrollmentStatusView, send } from "@/lib/messages";

interface Pending {
  id: string;
  glob: string;
}

// The popup: connection status, the per-site allowlist (with revoke), and the
// new-origin approval prompt. Event-driven - it refreshes on storage.onChanged
// (pendingAllow/allowlist) instead of polling.
export function PopupApp() {
  const { t } = useI18n();
  const [connected, setConnected] = useState(false);
  const [enroll, setEnroll] = useState<EnrollmentStatusView | undefined>();
  const [list, setList] = useState<string[]>([]);
  const [pending, setPending] = useState<Pending | null>(null);

  const refresh = useCallback(async () => {
    const status = await send<{ nativeConnected?: boolean }>({ type: "get_status" });
    setConnected(Boolean(status?.nativeConnected));
    setEnroll(await send<EnrollmentStatusView>({ type: "get_enrollment" }));
    const al = await send<{ list?: string[] }>({ type: "get_allowlist" });
    setList(al?.list ?? []);
    const { pendingAllow } = await browser.storage.local.get("pendingAllow");
    const parsed = PendingAllowSchema.safeParse(pendingAllow);
    setPending(parsed.success ? parsed.data : null);
  }, []);

  useEffect(() => {
    void refresh();
    const onChange = (changes: Record<string, unknown>, area: string) => {
      if (area === "local" && ("pendingAllow" in changes || "allowlist" in changes)) void refresh();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => browser.storage.onChanged.removeListener(onChange);
  }, [refresh]);

  const statusKey: MessageKey = enroll?.blocked
    ? enroll.state === "pending"
      ? "popup.status_blocked_pending"
      : enroll.state === "compromised"
        ? "popup.status_blocked_compromised"
        : "popup.status_blocked_unpaired"
    : connected
      ? "popup.status_connected"
      : "popup.status_disconnected";
  const dotClass = enroll?.blocked || !connected ? "bg-danger" : "bg-brand";

  const resolvePending = async (allow: boolean) => {
    if (!pending) return;
    if (allow) {
      const pattern = pending.glob.endsWith("/*") ? pending.glob : `${pending.glob}*`;
      const granted = await browser.permissions.request({ origins: [pattern] }).catch(() => false);
      if (!granted) {
        await send({ type: "resolve_allow", id: pending.id, allow: false });
        setPending(null);
        return;
      }
    }
    await send({ type: "resolve_allow", id: pending.id, allow });
    setPending(null);
    void refresh();
  };

  const removeSite = async (glob: string) => {
    await send({ type: "remove_allow", glob });
    void refresh();
  };

  return (
    <div className="flex flex-col gap-3 p-4">
      <div className="flex items-center gap-2">
        <span className={`inline-block size-2.5 rounded-full ${dotClass}`} />
        <span className="text-sm font-medium">{t(statusKey)}</span>
      </div>

      {pending && (
        <div className="rounded-xl border border-warn-edge bg-warn-surface p-3">
          <div className="mb-1 text-sm font-semibold">{t("popup.pending_title")}</div>
          <code className="mb-2 block break-all font-mono text-xs">{pending.glob}</code>
          <div className="flex justify-end gap-2">
            <Button onClick={() => void resolvePending(false)}>{t("common.deny")}</Button>
            <Button variant="primary" onClick={() => void resolvePending(true)}>
              {t("common.allow")}
            </Button>
          </div>
        </div>
      )}

      <div>
        <div className="mb-1 text-xs font-bold uppercase tracking-wider text-muted">
          {t("popup.allowed_sites")}
        </div>
        {list.length === 0 ? (
          <div className="rounded-lg border border-dashed border-edge p-3 text-center text-xs text-faint">
            {t("popup.no_sites")}
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-edge">
            {list.map((glob) => (
              <div
                key={glob}
                className="flex items-center justify-between border-b border-edge-soft px-3 py-2 last:border-b-0"
              >
                <code className="truncate font-mono text-xs">{glob}</code>
                <Button variant="ghost" className="px-2 py-1" onClick={() => void removeSite(glob)}>
                  {t("common.remove")}
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>

      <Button onClick={() => browser.runtime.openOptionsPage()}>{t("popup.open_settings")}</Button>
    </div>
  );
}
