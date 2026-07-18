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
        return (
          <span className="flex items-center gap-2 font-semibold">
            <span className="status-dot live" />
            {t("kill.state_alive")}
          </span>
        );
      case "killed":
        return (
          <span className="flex items-center gap-2 font-semibold text-danger">
            <span className="status-dot down" />
            {t("kill.state_killed")}
          </span>
        );
      case "unknown":
        return (
          <span className="flex items-center gap-2 font-semibold text-danger">
            <span className="status-dot down" />
            {t("kill.state_unknown")}
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-2 text-text-3">
            <span className="status-dot" />
            {t("kill.state_unmirrored")}
          </span>
        );
    }
  };

  return (
    <div className="flex items-start gap-3.5 py-1">
      <div className="min-w-0 flex-1">
        <div className="text-[13px]">{stateLine()}</div>
        <p className="consequence mt-1">{t("kill.desc")}</p>
        <div className="mt-1 text-xs text-text-3">{t("kill.release_note")}</div>
        {view?.at !== undefined && (
          <div className="tnum mt-1.5 font-mono text-[11px] text-text-4">
            {t("kill.updated", [new Date(view.at).toLocaleString()])}
          </div>
        )}
        {view && !view.ok && view.error && (
          <div className="mt-2 text-xs font-semibold text-danger">
            {t("kill.failed", [view.error])}
          </div>
        )}
        {actionError && <div className="mt-2 text-xs font-semibold text-danger">{actionError}</div>}
      </div>
      <Button variant={killed ? "default" : "danger"} onClick={() => void toggle()} disabled={busy}>
        {killed ? t("kill.release") : t("kill.engage")}
      </Button>
    </div>
  );
}
