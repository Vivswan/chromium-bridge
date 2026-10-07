import type { PresenceRequestFrame } from "@chromium-bridge/shared/generated/envelope";
import type { KillView } from "@chromium-bridge/shared/runtime-msg";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";
import { ceremonyFailure, refusalSentence } from "@/lib/refusals";
import { assert } from "@/lib/shared/webauthn-ceremony";

// The kill-switch panel: one prominent switch that halts all bridge activity everywhere, and its release behind
// the host's presence request. Everything here goes through the SW router (extension-page senders only) and is
// RELAYED to the native host, which performs the transition and answers with the resulting state: this panel can
// only ask, never decide. Event-driven: the SW-only mirror is watched via storage.onChanged, so a kill or release
// from any surface reflects here without polling.
//
//   engage   one click, no gate: the brake must be one action from every surface
//   release  kill_release -> the host's presence request -> this browser's authenticator signs it (or, when the
//            request admits no credential, the user confirms here and the host decides whether that may count)
//            -> the answer's verdict is the release outcome (lib/webauthn/exchange.ts claimKillRelease), so an
//            unwritable record is a refusal here and the mirror shows the rest
type Release =
  | { kind: "idle" }
  | { kind: "asking" }
  | { kind: "tapping" }
  | { kind: "confirm_window"; request: PresenceRequestFrame }
  | { kind: "confirming" }
  | { kind: "refused"; reason: string };

const RELEASE_BUSY: ReadonlySet<Release["kind"]> = new Set(["asking", "tapping", "confirming"]);

export function KillSwitchPanel() {
  const { t } = useI18n();
  const [view, setView] = useState<KillView | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [release, setRelease] = useState<Release>({ kind: "idle" });

  const refresh = useCallback(async () => {
    setView(await send({ type: "get_kill" }));
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
    // Engaging is deliberately zero-friction: the brake must be one action from every surface.
    setBusy(true);
    setActionError(null);
    const r = await send({ type: "set_kill", on: true });
    if (!r.ok) setActionError(t("kill.failed", [r.error ?? t("kill.no_reply")]));
    setView(r);
    setBusy(false);
  };

  const settleRelease = (verdict: { ok: true } | { ok: false; error: string }) => {
    setRelease(verdict.ok ? { kind: "idle" } : { kind: "refused", reason: verdict.error });
  };

  const tap = async (request: PresenceRequestFrame) => {
    setRelease({ kind: "tapping" });
    let response: Awaited<ReturnType<typeof assert>>;
    try {
      response = await assert(request);
    } catch (e) {
      setRelease({ kind: "refused", reason: ceremonyFailure(e) });
      return;
    }
    settleRelease(
      await send({ type: "webauthn_presence_assert", nonce: request.nonce, ...response }),
    );
  };

  const startRelease = async () => {
    setRelease({ kind: "asking" });
    const asked = await send({ type: "kill_release" });
    if (!asked.ok) {
      setRelease({ kind: "refused", reason: asked.error });
      return;
    }
    // An empty allow list is the host saying this browser has no enrolled credential, so the window may answer.
    // The host re-checks that when the answer arrives (software_confirmation_not_allowed otherwise).
    if (asked.request.allowed_credential_ids.length === 0) {
      setRelease({ kind: "confirm_window", request: asked.request });
      return;
    }
    await tap(asked.request);
  };

  const confirmWindow = async (request: PresenceRequestFrame) => {
    setRelease({ kind: "confirming" });
    settleRelease(await send({ type: "webauthn_presence_confirm", nonce: request.nonce }));
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

  const releaseBusy = RELEASE_BUSY.has(release.kind);

  return (
    <div className="py-1">
      <div className="flex items-start gap-3.5">
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
        {killed && release.kind !== "confirm_window" && (
          <Button onClick={() => void startRelease()} disabled={releaseBusy}>
            {t("kill.release")}
          </Button>
        )}
      </div>

      {release.kind === "confirm_window" && (
        <div className="mt-3 rounded-lg border border-pending-edge bg-pending-dim px-3.5 py-3">
          <div className="flex items-center gap-2 text-[13px] font-semibold">
            <span className="status-dot pending" />
            {t("kill.release_confirm_title")}
          </div>
          <p className="consequence mt-1">{t("kill.release_confirm_desc")}</p>
          <div className="mt-2 font-mono text-xs text-text-2">{release.request.action}</div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="pending" onClick={() => void confirmWindow(release.request)}>
              {t("kill.release_confirm")}
            </Button>
            <Button variant="ghost" onClick={() => setRelease({ kind: "idle" })}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      )}
      {releaseBusy && (
        <div role="status" className="mt-2 text-xs text-text-3">
          {release.kind === "asking" && t("kill.release_asking")}
          {release.kind === "tapping" && t("kill.release_tap")}
          {release.kind === "confirming" && t("kill.release_confirming")}
        </div>
      )}
      <div
        role="alert"
        className={
          release.kind === "refused" ? "mt-2 text-xs font-semibold text-danger" : "sr-only"
        }
      >
        {release.kind === "refused" &&
          t("kill.release_failed", [refusalSentence(t, release.reason)])}
      </div>
    </div>
  );
}
