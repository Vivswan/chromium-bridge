import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { refusalSentence } from "@/lib/refusals";
import type { PresenceActControls } from "./usePresenceAct";

/** A presence act's progress as every panel shows it: the host's action while the tap or the click that
 * approves it is awaited, the step line, and the refusal as one sentence. `confirmLabel` is the window's
 * button, `refused` wraps the sentence in the panel's own line.
 *
 * While the tap is awaited the action sits inside the live region: the authenticator's prompt takes the focus
 * the moment it opens, so what a screen reader announces then must name what the tap approves. */
export function PresenceActStatus({
  presence,
  confirmLabel,
  refused,
}: {
  presence: PresenceActControls;
  confirmLabel: string;
  refused: (sentence: string) => string;
}) {
  const { t } = useI18n();
  const { act } = presence;
  return (
    <>
      {act.kind === "confirm_window" && (
        <div className="mt-3 rounded-lg border border-pending-edge bg-pending-dim px-3.5 py-3">
          <div className="flex items-center gap-2 text-[13px] font-semibold">
            <span className="status-dot pending" />
            {t("presence.window_title")}
          </div>
          <p className="consequence mt-1">{t("presence.window_desc")}</p>
          <div className="mt-2 font-mono text-xs text-text-2">{act.request.action}</div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="pending" onClick={() => void presence.confirmWindow(act.request)}>
              {confirmLabel}
            </Button>
            <Button variant="ghost" onClick={presence.cancel}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      )}
      {(act.kind === "asking" || act.kind === "tapping" || act.kind === "confirming") && (
        <div role="status" className="mt-2 text-xs text-text-3">
          {act.kind === "asking" && t("presence.asking")}
          {act.kind === "tapping" && (
            <>
              <div>{t("presence.tapping")}</div>
              <div className="mt-1 font-mono text-text-2">{act.request.action}</div>
            </>
          )}
          {act.kind === "confirming" && t("presence.confirming")}
        </div>
      )}
      <div
        role="alert"
        className={act.kind === "refused" ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
      >
        {act.kind === "refused" && refused(refusalSentence(t, act.reason))}
      </div>
    </>
  );
}
