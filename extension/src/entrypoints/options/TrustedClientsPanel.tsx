import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { type ClientListView, send } from "@/lib/messages";

// The ADR-0025 trusted-client panel: the MCP-client harnesses this machine's
// bridge admits (ADR-0024), with a revoke per entry. Revoking takes effect
// immediately at the enforcement point: the allowlist is rewritten and the
// revocation epoch bumped in one critical section, so a live broker drops the
// client's connections and refuses its re-attach. The list lives host-side;
// reads and revokes go through the SW router to the native host, so this
// panel shows a not-connected state when no host is up.
export function TrustedClientsPanel() {
  const { t } = useI18n();
  const [view, setView] = useState<ClientListView | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setView((await send<ClientListView>({ type: "get_clients" })) ?? null);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const revoke = async (name: string) => {
    if (!window.confirm(t("clients.revoke_confirm", [name]))) return;
    setBusy(true);
    setActionError(null);
    const r = await send<{ ok: boolean; error?: string }>({ type: "revoke_client", name });
    if (!r?.ok) setActionError(t("clients.revoke_failed", [r?.error ?? t("clients.no_reply")]));
    await refresh();
    setBusy(false);
  };

  const anchorLabel = (kind: "hash" | "team_id") =>
    kind === "team_id" ? t("clients.anchor_team") : t("clients.anchor_hash");

  return (
    <div className="rounded-xl border border-edge p-3.5">
      <div className="flex items-start justify-between gap-3">
        <div className="text-xs text-muted">{t("clients.desc")}</div>
        <Button variant="ghost" onClick={() => void refresh()} disabled={busy}>
          {t("clients.refresh")}
        </Button>
      </div>

      {view === null && <div className="mt-2 text-muted">{t("clients.loading")}</div>}

      {view && !view.ok && (
        <div className="mt-2 text-xs font-semibold text-danger-strong">
          {t("clients.error", [view.error ?? t("clients.no_reply")])}
        </div>
      )}

      {view?.ok && view.enrolled === false && (
        <div className="mt-2 text-xs font-semibold text-danger-strong">
          {t("clients.unenrolled")}
        </div>
      )}

      {view?.ok && view.enrolled && (view.clients?.length ?? 0) === 0 && (
        <div className="mt-2 text-xs text-muted">{t("clients.empty")}</div>
      )}

      {view?.ok && view.enrolled && (view.clients?.length ?? 0) > 0 && (
        <ul className="mt-2 divide-y divide-edge-soft">
          {view.clients?.map((c) => (
            <li key={c.name} className="flex items-center gap-3 py-2">
              <div className="min-w-0 flex-1">
                <div className="font-mono text-[13px] font-semibold">{c.name}</div>
                <div className="truncate text-[11px] text-faint">
                  {anchorLabel(c.anchor.kind)}: {c.anchor.value}
                </div>
              </div>
              <Button variant="ghost" onClick={() => void revoke(c.name)} disabled={busy}>
                {t("clients.revoke")}
              </Button>
            </li>
          ))}
        </ul>
      )}

      {actionError && (
        <div className="mt-2 text-xs font-semibold text-danger-strong">{actionError}</div>
      )}
    </div>
  );
}
