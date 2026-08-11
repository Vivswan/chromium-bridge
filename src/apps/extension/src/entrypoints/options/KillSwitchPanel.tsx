import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
// Type-only: the SW's own KillView declaration (lib/background/kill.ts), so
// this panel cannot re-declare a drifted mirror of it.
import type { KillView } from "@/lib/background/kill";
import { send } from "@/lib/messages";

// The ADR-0030 kill-switch panel: one prominent, explicit switch that halts
// all bridge activity everywhere. ENGAGE-ONLY (ADR-0032 decision 6): the
// host refuses `kill_release` from the extension, so releasing lives in the
// Chromium Bridge app and `chromium-bridge unkill` - this panel engages and
// shows the state, never releases. Everything here goes through the SW
// router (extension-page senders only) and is RELAYED to the native host,
// which performs the transition and answers with the resulting state - this
// panel can only ask, never decide. Event-driven: the SW-only mirror is
// watched via storage.onChanged, so a kill or unkill from any surface
// reflects here without polling.
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

  const engage = async () => {
    // Engaging is deliberately zero-friction (ADR-0030): the brake must be
    // one action from every surface. Releasing restores capability, so it is
    // not offered here at all: the host refuses kill_release from the
    // extension (ADR-0032 decision 6), and release lives behind the app's
    // presence gate or `chromium-bridge unkill`.
    setBusy(true);
    setActionError(null);
    try {
      const r = await send<KillView>({ type: "set_kill", on: true });
      if (!r?.ok) setActionError(t("kill.failed", [r?.error ?? t("kill.no_reply")]));
      setView(r ?? null);
    } catch (e) {
      setActionError(t("kill.failed", [String(e)]));
    } finally {
      setBusy(false);
    }
  };

  const stateLine = () => {
    // Fail-closed display: a green "alive" needs a FRESH positive answer
    // (view.ok). A stale mirror behind an unreachable host downgrades to a
    // neutral last-known line; no state at all renders severed, never a
    // neutral controllable idle.
    switch (view?.state) {
      case "alive":
        return view.ok ? (
          <span className="flex items-center gap-2 font-semibold">
            <span className="status-dot live" />
            {t("kill.state_alive")}
          </span>
        ) : (
          <span className="flex items-center gap-2 text-text-2">
            <span className="status-dot" />
            {t("kill.state_alive_stale")}
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
        // Never heard a state AND could not read one: severed until a read
        // succeeds. Only a fresh ok answer with no state (not reachable in
        // practice: the host always reports a state) stays neutral.
        return view?.ok ? (
          <span className="flex items-center gap-2 text-text-3">
            <span className="status-dot" />
            {t("kill.state_unmirrored")}
          </span>
        ) : (
          <span className="flex items-center gap-2 font-semibold text-danger">
            <span className="status-dot down" />
            {t("kill.state_severed")}
          </span>
        );
    }
  };

  return (
    <div className="flex items-start gap-3.5 py-1">
      <div className="min-w-0 flex-1">
        <div className="text-[13px]">{stateLine()}</div>
        <p className="consequence mt-1">{t("kill.desc")}</p>
        <div className="mt-1 text-xs text-text-3">{t("kill.release_pointer")}</div>
        {view?.at !== undefined && (
          <div className="tnum mt-1.5 font-mono text-[11px] text-text-4">
            {t("kill.updated", [new Date(view.at).toLocaleString()])}
          </div>
        )}
        {view && !view.ok && view.error && (
          <div role="alert" className="mt-2 text-xs font-semibold text-danger">
            {t("kill.failed", [view.error])}
          </div>
        )}
        <div
          role="alert"
          className={actionError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
        >
          {actionError}
        </div>
      </div>
      {!killed && (
        <Button variant="danger" onClick={() => void engage()} disabled={busy}>
          {t("kill.engage")}
        </Button>
      )}
    </div>
  );
}
