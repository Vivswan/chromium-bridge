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

/** The SW's answer to get_kill (lib/background/kill.ts KillView). */
interface KillView {
  ok: boolean;
  state?: "alive" | "killed" | "unknown";
  at?: number;
  error?: string;
}

function BridgeIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path
        d="M6.2 9.8l3.6-3.6M7.3 4.9l1.2-1.2a2.6 2.6 0 0 1 3.8 3.8l-1.2 1.2M8.7 11.1l-1.2 1.2a2.6 2.6 0 0 1-3.8-3.8l1.2-1.2"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

function KillIcon({ size = 12 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 1.5v6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <path
        d="M4.5 3.6a6 6 0 1 0 7 0"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

type GateState = "on" | "pending" | "down" | "idle";

// The three trust gates (client -> host -> browser) at dot scale.
function MicroPipeline({
  gates,
  label,
}: {
  gates: [GateState, GateState, GateState];
  label: string;
}) {
  const dot = (g: GateState) => (g === "idle" ? "p-dot" : `p-dot ${g}`);
  const lineOn = (a: GateState, b: GateState) =>
    a === "on" && b === "on" ? "p-line on" : "p-line";
  return (
    <span className="pipeline-micro" role="img" aria-label={label}>
      <span className={dot(gates[0])} />
      <span className={lineOn(gates[0], gates[1])} />
      <span className={dot(gates[1])} />
      <span className={lineOn(gates[1], gates[2])} />
      <span className={dot(gates[2])} />
    </span>
  );
}

function fmtAgo(at: number): string {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

/** "https://github.com/*" -> "github.com" for the loud origin line. */
function displayOrigin(glob: string): string {
  return glob.replace(/^https?:\/\//, "").replace(/\/\*?$/, "");
}

// The popup: connection status as the micro trust pipeline, the per-site
// allowlist (with revoke), the new-origin approval prompt, the pairing
// approve-half, and the engage-only kill switch row. Event-driven - it
// refreshes on storage.onChanged (pendingAllow/allowlist/bridgeKillMirror)
// instead of polling.
export function PopupApp() {
  const { t } = useI18n();
  const [connected, setConnected] = useState(false);
  const [enroll, setEnroll] = useState<EnrollmentStatusView | undefined>();
  const [list, setList] = useState<string[]>([]);
  const [pending, setPending] = useState<Pending | null>(null);
  const [kill, setKill] = useState<KillView | null>(null);
  const [killBusy, setKillBusy] = useState(false);
  const [killError, setKillError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const status = await send<{ nativeConnected?: boolean }>({ type: "get_status" });
    setConnected(Boolean(status?.nativeConnected));
    setEnroll(await send<EnrollmentStatusView>({ type: "get_enrollment" }));
    const al = await send<{ list?: string[] }>({ type: "get_allowlist" });
    setList(al?.list ?? []);
    const { pendingAllow } = await browser.storage.local.get("pendingAllow");
    const parsed = PendingAllowSchema.safeParse(pendingAllow);
    setPending(parsed.success ? parsed.data : null);
    try {
      setKill((await send<KillView>({ type: "get_kill" })) ?? null);
    } catch {
      setKill(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const onChange = (changes: Record<string, unknown>, area: string) => {
      if (
        area === "local" &&
        ("pendingAllow" in changes || "allowlist" in changes || "bridgeKillMirror" in changes)
      )
        void refresh();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => browser.storage.onChanged.removeListener(onChange);
  }, [refresh]);

  const killed = kill?.state === "killed";
  // The host reports "unknown" when its kill state is unreadable and it is
  // FAILING CLOSED (all activity refused) - never render that as live.
  const killUnknown = kill?.state === "unknown";
  const version = browser.runtime.getManifest().version;

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

  // Engaging is deliberately zero-friction (ADR-0030): the brake must be one
  // action from every surface. This popup can only engage, never release.
  const engageKill = async () => {
    setKillBusy(true);
    setKillError(null);
    try {
      const r = await send<KillView>({ type: "set_kill", on: true });
      if (!r?.ok) setKillError(t("kill.failed", [r?.error ?? t("kill.no_reply")]));
      else setKill(r);
    } catch (e) {
      setKillError(t("kill.failed", [String(e)]));
    } finally {
      setKillBusy(false);
    }
  };

  const enrollAct = async (type: "enroll_approve" | "enroll_reject") => {
    await send({ type });
    void refresh();
  };

  // Head pill + pipeline per state. The pipeline's gates are client -> host
  // -> browser; the client dot stays neutral because this popup cannot see
  // client attestation (that check lives host-side) - it never overclaims.
  let pill: { className: string; dot: string; label: MessageKey };
  let gates: [GateState, GateState, GateState];
  let statusKey: MessageKey;
  if (killed) {
    pill = { className: "pill pill-danger", dot: "status-dot down", label: "popup.pill_killed" };
    gates = ["down", "down", "down"];
    statusKey = "popup.status_killed";
  } else if (killUnknown) {
    pill = { className: "pill pill-danger", dot: "status-dot down", label: "popup.pill_blocked" };
    gates = ["down", "down", "down"];
    statusKey = "popup.status_kill_unknown";
  } else if (enroll?.blocked) {
    if (enroll.state === "compromised") {
      pill = { className: "pill pill-danger", dot: "status-dot down", label: "popup.pill_blocked" };
      gates = ["idle", "down", "idle"];
      statusKey = "popup.status_blocked_compromised";
    } else {
      pill = {
        className: "pill pill-pending",
        dot: "status-dot pending",
        label: "popup.pill_pair",
      };
      gates = ["idle", connected ? "on" : "idle", "pending"];
      statusKey =
        enroll.state === "pending"
          ? "popup.status_blocked_pending"
          : "popup.status_blocked_unpaired";
    }
  } else if (pending) {
    pill = {
      className: "pill pill-pending",
      dot: "status-dot pending",
      label: "popup.pill_needs_you",
    };
    gates = ["idle", "on", "pending"];
    statusKey = "popup.status_pending_origin";
  } else if (connected) {
    pill = { className: "pill pill-live", dot: "status-dot live", label: "popup.pill_live" };
    gates = ["idle", "on", "on"];
    statusKey =
      enroll?.state === "pinned" ? "popup.status_connected_verified" : "popup.status_connected";
  } else {
    pill = { className: "pill", dot: "status-dot", label: "popup.pill_offline" };
    gates = ["idle", "idle", "idle"];
    statusKey = "popup.status_disconnected";
  }

  // De-emphasis by ink tier, not opacity: text drops one level and stays AA;
  // only the pipeline dots actually fade.
  const microStatus = (dimmed: boolean) => (
    <div className="flex items-center gap-2.5">
      <span className={dimmed ? "opacity-50" : ""}>
        <MicroPipeline gates={gates} label={t(statusKey)} />
      </span>
      <span className={`min-w-0 text-xs ${dimmed ? "text-text-3" : "text-text-2"}`}>
        {t(statusKey)}
      </span>
      {killed && kill?.at !== undefined && (
        <span className="tnum ml-auto whitespace-nowrap font-mono text-[10px] text-text-3">
          {t("popup.engaged_ago", [fmtAgo(kill.at)])}
        </span>
      )}
    </div>
  );

  // The panic row: engage-only. Always a plain row - never dimmed, never boxed.
  const panicRow = (noteKey: MessageKey) => (
    <div className="border-t border-edge pt-3">
      <div className="flex items-center gap-2">
        <Button
          variant="danger"
          className="shrink-0 whitespace-nowrap"
          onClick={() => void engageKill()}
          disabled={killBusy}
        >
          <KillIcon />
          {t("kill.engage")}
        </Button>
        <span className="text-[11px] text-text-3">{t(noteKey)}</span>
      </div>
      {killError && <p className="mt-1.5 text-xs font-semibold text-danger">{killError}</p>}
    </div>
  );

  // The pairing state's footer carries the spec's promise instead of the
  // settings link: until you pair, this extension does nothing.
  const pairPending =
    !killed &&
    enroll?.blocked === true &&
    enroll.state === "pending" &&
    Boolean(enroll.fingerprint);

  const foot = (
    <div className="mt-auto flex items-center justify-between border-t border-edge px-3.5 py-2.5">
      {pairPending ? (
        <span className="text-[11px] text-text-3">{t("popup.pair_foot")}</span>
      ) : (
        <button
          type="button"
          className="inline-flex cursor-pointer items-center gap-1.5 border-none bg-transparent p-0 text-xs font-medium text-text-2 hover:text-text-1"
          onClick={() => browser.runtime.openOptionsPage()}
        >
          <span className="text-text-3">
            <BridgeIcon size={12} />
          </span>
          {t("popup.open_settings")}
        </button>
      )}
      <span className="font-mono text-[10px] text-text-4">{t("popup.ext_version", [version])}</span>
    </div>
  );

  return (
    <div className="flex min-h-[120px] flex-col bg-surface-0 text-text-1">
      <div className="flex items-center gap-2 border-b border-edge px-3.5 py-2.5">
        <BridgeIcon />
        <span className="text-[13px] font-semibold">{t("app.name")}</span>
        <span className={`${pill.className} ml-auto`}>
          <span className={pill.dot} />
          {t(pill.label)}
        </span>
      </div>

      <div className="flex flex-col gap-3 px-3.5 pb-3.5 pt-3">
        {killed ? (
          <>
            <div>
              <div className="flex items-center gap-2 text-danger">
                <KillIcon size={14} />
                <span className="text-[13px] font-semibold">{t("popup.killed_line")}</span>
              </div>
              <p className="consequence mt-1.5">{t("popup.killed_consequence")}</p>
            </div>
            {microStatus(false)}
            <div>
              <p className="text-xs leading-relaxed text-text-2">
                {t("popup.killed_release_note")}
              </p>
              <Button
                className="mt-2 w-full py-2 text-[13px]"
                onClick={() => browser.runtime.openOptionsPage()}
              >
                <BridgeIcon size={12} />
                {t("popup.killed_release_cta")}
              </Button>
            </div>
          </>
        ) : enroll?.blocked && enroll.state === "pending" && enroll.fingerprint ? (
          <>
            {microStatus(false)}
            <div>
              <div className="section-title mb-1.5">{t("popup.pair_compare")}</div>
              {/* reading order per first-run.html: explain, then the code,
                  then the choice - with the safe exit as the filled default */}
              <p className="text-xs leading-snug text-text-2">{t("popup.pair_explainer")}</p>
              {/* open and centered - size does the work, not a box */}
              <div className="px-0 py-2 text-center">
                <div className="break-all font-mono text-[15px] font-bold leading-relaxed tracking-[0.12em] text-text-1">
                  {enroll.fingerprint}
                </div>
              </div>
              <div className="mt-1 flex gap-2">
                <Button
                  variant="primary"
                  className="flex-1 py-2 text-[13px]"
                  onClick={() => void enrollAct("enroll_reject")}
                >
                  {t("popup.pair_reject")}
                </Button>
                <Button
                  className="flex-1 py-2 text-[13px]"
                  onClick={() => void enrollAct("enroll_approve")}
                >
                  {t("popup.pair_approve")}
                </Button>
              </div>
              <p className="consequence mt-2">{t("popup.pair_consequence")}</p>
              <p className="consequence mt-1">{t("popup.pair_outcome")}</p>
            </div>
            {panicRow("popup.kill_note_pair")}
          </>
        ) : enroll?.blocked ? (
          <>
            {microStatus(false)}
            <p className="text-xs leading-relaxed text-text-2">
              {t(
                enroll.state === "compromised"
                  ? "popup.blocked_compromised_hint"
                  : "popup.blocked_unpaired_hint",
              )}
            </p>
            {panicRow("popup.kill_note_pair")}
          </>
        ) : (
          <>
            {pending && (
              <div className="rounded-lg border border-pending-edge bg-pending-dim px-3.5 py-3">
                <div className="section-title mb-0.5 text-pending">{t("popup.pending_label")}</div>
                <div className="my-1 break-all font-mono text-lg font-bold text-text-1">
                  {displayOrigin(pending.glob)}
                </div>
                <p className="text-xs leading-snug text-text-2">{t("popup.pending_ask")}</p>
                <div className="mt-2.5 flex gap-2">
                  <Button
                    variant="primary"
                    className="flex-1 py-2 text-[13px]"
                    onClick={() => void resolvePending(false)}
                  >
                    {t("common.deny")}
                  </Button>
                  <Button
                    className="flex-1 py-2 text-[13px]"
                    onClick={() => void resolvePending(true)}
                  >
                    {t("popup.pending_allow_on", [displayOrigin(pending.glob)])}
                  </Button>
                </div>
                <p className="consequence mt-2">{t("popup.pending_consequence")}</p>
              </div>
            )}

            {microStatus(Boolean(pending))}

            <div>
              <div className="section-title mb-1">{t("popup.allowed_sites")}</div>
              {list.length === 0 ? (
                <p className="py-1 text-xs text-text-3">{t("popup.no_sites")}</p>
              ) : (
                <div className="flex flex-col">
                  {list.map((glob) => (
                    <div
                      key={glob}
                      className="flex items-center gap-2 border-b border-edge py-1.5 last:border-b-0"
                    >
                      <code
                        className={`min-w-0 truncate font-mono text-xs ${pending ? "text-text-2" : "text-text-1"}`}
                      >
                        {displayOrigin(glob)}
                      </code>
                      <button
                        type="button"
                        className="-my-0.5 ml-auto cursor-pointer rounded-sm border-none bg-transparent px-2 py-1 text-[11px] font-medium text-text-2 hover:bg-danger-dim hover:text-danger"
                        aria-label={`${t("common.remove")} ${displayOrigin(glob)}`}
                        onClick={() => void removeSite(glob)}
                      >
                        {t("common.remove")}
                      </button>
                    </div>
                  ))}
                  <p className="consequence mt-1.5">{t("popup.sites_consequence")}</p>
                </div>
              )}
            </div>

            {panicRow(pending ? "popup.kill_note_denies" : "popup.kill_note_release")}
          </>
        )}
      </div>

      {foot}
    </div>
  );
}
