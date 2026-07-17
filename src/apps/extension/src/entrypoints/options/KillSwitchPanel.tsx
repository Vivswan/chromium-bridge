import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";

/** The SW's answer to get_kill / set_kill (lib/background/kill.ts KillView). */
interface KillView {
  ok: boolean;
  state?: "alive" | "killed" | "unknown";
  at?: number;
  error?: string;
}

// The ADR-0030 kill-switch panel: one prominent, explicit switch that halts
// all bridge activity everywhere until it is just as explicitly released.
// Everything here goes through the SW router (extension-page senders only)
// and is RELAYED to the native host, which performs the transition and
// answers with the resulting state - this panel can only ask, never decide.
// Event-driven: the SW-only mirror is watched via storage.onChanged, so a
// kill or unkill from the CLI reflects here without polling.
export function KillSwitchPanel() {
  const { t } = useI18n();
  const [view, setView] = useState<KillView | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setView((await send<KillView>({ type: "get_kill" })) ?? null);
    } catch (e) {
      console.warn("[bb] kill panel refresh failed", e);
    }
  }, []);

  useEffect(() => {
    void refresh();
    // The mirror lives in the SW's trusted storage; options pages are trusted
    // contexts, so its changes are observable here (read-only) and drive the
    // refresh - including transitions the CLI made while this page was open.
    const onChanged = (changes: Record<string, unknown>, area: string) => {
      if (area === "local" && "bridgeKillMirror" in changes) void refresh();
    };
    browser.storage.onChanged.addListener(onChanged);
    return () => browser.storage.onChanged.removeListener(onChanged);
  }, [refresh]);

  const killed = view?.state === "killed";

  const toggle = async () => {
    // Engaging is deliberately zero-friction (ADR-0030): the brake must be
    // one action from every surface. Releasing restores capability, so it
    // carries the explicit confirmation - the interactive floor of the
    // user-presence ladder, which the host audits as auth=extension_confirm
    // (hardware presence takes over when Phase 8 lands).
    if (killed && !window.confirm(t("kill.release_confirm"))) return;
    setBusy(true);
    setActionError(null);
    try {
      const r = await send<KillView>({ type: "set_kill", on: !killed });
      if (!r?.ok) setActionError(t("kill.failed", [r?.error ?? t("kill.no_reply")]));
      setView(r ?? null);
    } catch (e) {
      setActionError(t("kill.failed", [String(e)]));
    } finally {
      setBusy(false);
    }
  };

  const stateLine = () => {
    switch (view?.state) {
      case "alive":
        return <span className="font-semibold">{t("kill.state_alive")}</span>;
      case "killed":
        return <span className="font-semibold text-danger-strong">{t("kill.state_killed")}</span>;
      case "unknown":
        return <span className="font-semibold text-danger-strong">{t("kill.state_unknown")}</span>;
      default:
        return <span className="text-muted">{t("kill.state_unmirrored")}</span>;
    }
  };

  return (
    <div className="rounded-xl border border-edge p-3.5">
      <div className="text-xs text-muted">{t("kill.desc")}</div>
      <div className="mt-3 flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm">{stateLine()}</div>
          {view?.at !== undefined && (
            <div className="mt-0.5 text-[11px] text-faint">
              {t("kill.updated", [new Date(view.at).toLocaleString()])}
            </div>
          )}
        </div>
        <Button
          variant={killed ? "primary" : "danger"}
          onClick={() => void toggle()}
          disabled={busy}
        >
          {killed ? t("kill.release") : t("kill.engage")}
        </Button>
      </div>
      {view && !view.ok && view.error && (
        <div className="mt-2 text-xs font-semibold text-danger-strong">
          {t("kill.failed", [view.error])}
        </div>
      )}
      {actionError && (
        <div className="mt-2 text-xs font-semibold text-danger-strong">{actionError}</div>
      )}
    </div>
  );
}
