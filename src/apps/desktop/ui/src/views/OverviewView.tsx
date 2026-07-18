import { useEffect, useRef, useState } from "react";
import {
  ChipMono,
  Consequence,
  Dot,
  ErrorNote,
  Mono,
  Pill,
  SpecLabel,
  StatusDot,
  TouchIdChip,
  ViewShell,
} from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { authLabel } from "@/lib/auth-label";
import { browserDisplayName, formatBrowserList } from "@/lib/browser-names";
import { formatFingerprint } from "@/lib/fingerprint";
import { api, errorText, type FirstRunReport } from "@/lib/tauri";
import { useAppStore } from "@/store";

/* ------------------------------------------------------------------ */
/* Trust map: the fan-in/fan-out hub. Clients fan in to the host; the  */
/* host fans out to browsers. Every edge carries its own state: solid  */
/* green = attested + live, solid neutral = attested but not serving,  */
/* dashed = dormant (no trust established).                            */
/* ------------------------------------------------------------------ */

type EdgeState = "on" | "idle" | "off";

interface HubNode {
  key: string;
  name: string;
  meta: string;
  lit: boolean;
  dim: boolean;
  edge: EdgeState;
}

const NODE_H = 56;
const NODE_GAP = 10;
const LANE_W = 80;
const HOST_H = 122;

/** Collapse rule for >3 nodes per column: keep the 3 highest-priority
 * nodes (lit > plain > dim), then one dim "+N more" node whose single
 * dashed edge merges the rest. */
function collapseColumn(nodes: HubNode[], moreLabel: (n: number) => string): HubNode[] {
  if (nodes.length <= 3) return nodes;
  const rank = (n: HubNode) => (n.lit ? 0 : n.dim ? 2 : 1);
  const kept = [...nodes].sort((a, b) => rank(a) - rank(b)).slice(0, 3);
  const shown = nodes.filter((n) => kept.includes(n));
  const rest = nodes.length - shown.length;
  shown.push({
    key: "__more",
    name: moreLabel(rest),
    meta: "",
    lit: false,
    dim: true,
    edge: "off",
  });
  return shown;
}

function stackHeight(count: number): number {
  return count * NODE_H + Math.max(0, count - 1) * NODE_GAP;
}

function centers(count: number, laneH: number): number[] {
  const top = (laneH - stackHeight(count)) / 2;
  return Array.from({ length: count }, (_, i) => top + i * (NODE_H + NODE_GAP) + NODE_H / 2);
}

function Lane({
  dir,
  height,
  edges,
  label,
}: {
  dir: "in" | "out";
  height: number;
  edges: { y: number; state: EdgeState }[];
  label: string;
}) {
  const hostY = height / 2;
  const anyOn = edges.some((e) => e.state === "on");
  const labelTop =
    dir === "in" ? hostY + 9 : Math.min(Math.max((edges[0]?.y ?? hostY) - 26, 2), height - 18);
  return (
    <div className={`hub-lane hub-lane-${dir}`} style={{ height }} aria-hidden="true">
      <svg
        viewBox={`0 0 ${LANE_W} ${height}`}
        fill="none"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        {edges.map(({ y, state }) => {
          const path =
            dir === "in"
              ? `M0 ${y} C30 ${y} 50 ${hostY} 80 ${hostY}`
              : `M0 ${hostY} C30 ${hostY} 45 ${y} 78 ${y}`;
          const cls = state === "on" ? "edge-on" : state === "idle" ? "edge-idle" : "edge-off";
          return (
            <g key={`${y}`}>
              <path className={cls} d={path} strokeWidth="1" />
              {state === "on" &&
                (dir === "in" ? (
                  <path
                    className="edge-chev"
                    d={`M14 ${y - 4.5} 18.5 ${y} 14 ${y + 4.5}`}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                ) : (
                  <path
                    className="edge-chev"
                    d={`M65 ${y - 4.5} 69.5 ${y} 65 ${y + 4.5}`}
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                ))}
              {state === "off" && dir === "out" && (
                <circle cx="77" cy={y} r="1.8" fill="var(--text-4)" />
              )}
            </g>
          );
        })}
      </svg>
      {anyOn && (
        <span className="hub-lane-label" style={{ top: labelTop }}>
          {label}
        </span>
      )}
    </div>
  );
}

function HubNodeBox({ node }: { node: HubNode }) {
  return (
    <div className={`hub-node${node.lit ? " lit" : ""}${node.dim ? " dim" : ""}`}>
      <div className="hub-node-name">
        <Dot tone={node.lit ? "live" : "idle"} />
        {node.name}
      </div>
      {node.meta !== "" && <div className="hub-node-meta">{node.meta}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */

export function OverviewView() {
  const { t } = useI18n();
  const status = useAppStore((s) => s.status);
  const statusError = useAppStore((s) => s.statusError);
  const refreshStatus = useAppStore((s) => s.refreshStatus);
  const browsers = useAsync(api.browsersList);
  const enclave = useAsync(api.enclaveStatus);
  const clients = useAsync(api.clientsList);

  // First-launch detection (ADR-0029 as amended): the command only reports
  // which browsers exist and claims the shown-once marker; nothing touches a
  // browser's configuration until the user clicks Connect here or on the
  // Browsers page. The Rust side is single-flight (the marker is created
  // with create_new), and the ref keeps StrictMode's double-invoked dev
  // effect from firing the command twice.
  const [firstRun, setFirstRun] = useState<FirstRunReport | null>(null);
  const [firstRunError, setFirstRunError] = useState<string>();
  const firstRunStarted = useRef(false);
  const [connectReport, setConnectReport] = useState<{ lines: string[]; errors: string[] }>();
  const [busy, setBusy] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [releaseOpen, setReleaseOpen] = useState(false);
  const [releasedBy, setReleasedBy] = useState<string>();

  useEffect(() => {
    if (firstRunStarted.current) return;
    firstRunStarted.current = true;
    api
      .firstLaunchDetect()
      .then(setFirstRun)
      .catch((err: unknown) => setFirstRunError(errorText(err)));
  }, []);

  // The opt-in bulk path: one explicit click connects every detected
  // browser through the same user-initiated command as the per-browser
  // buttons. Sequential on purpose; the registrations share the install dir.
  const connectAll = async (keys: string[]) => {
    setBusy("connect-all");
    setConnectReport(undefined);
    const lines: string[] = [];
    const errors: string[] = [];
    for (const key of keys) {
      try {
        lines.push(...(await api.browserRegister(key)));
      } catch (err) {
        errors.push(`${key}: ${errorText(err)}`);
      }
    }
    setConnectReport({ lines, errors });
    setBusy(undefined);
    browsers.reload();
  };

  const engage = async () => {
    setBusy("engage");
    setActionError(undefined);
    setReleasedBy(undefined);
    try {
      await api.killEngage();
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setBusy(undefined);
      void refreshStatus();
    }
  };

  // Presence-gated: invoked ONLY from the confirm dialog below. The dialog
  // is what Floor::AppConfirm asserts (see the Rust seam).
  const confirmRelease = async () => {
    setBusy("release");
    setActionError(undefined);
    setReleasedBy(undefined);
    try {
      const outcome = await api.killRelease();
      setReleasedBy(outcome.auth);
      setReleaseOpen(false);
    } catch (err) {
      setActionError(errorText(err));
      setReleaseOpen(false);
    } finally {
      setBusy(undefined);
      void refreshStatus();
    }
  };

  /* ----- derive the map ----- */

  const killState = status?.kill.state;
  const engaged = killState === "engaged";
  // "serving" is only claimed when the kill state is provably off AND the
  // server socket answered; loading or unreadable never counts as off.
  const serving = status?.server.reachable === true && killState === "off";
  const keyPresent = enclave.data?.key === "present";
  const fingerprint = enclave.data?.fingerprint;

  const clientRows = clients.data?.clients ?? [];
  const clientNodes: HubNode[] =
    clientRows.length === 0
      ? [
          {
            key: "__none",
            name: t("overview.map_no_clients"),
            meta: t("overview.map_no_clients_meta"),
            lit: false,
            dim: true,
            edge: "off",
          },
        ]
      : clientRows.map((c) => ({
          key: c.name,
          name: c.name,
          meta: t("overview.client_paired", [new Date(c.addedUnix * 1000).toLocaleDateString()]),
          lit: serving,
          dim: false,
          edge: serving ? ("on" as const) : ("idle" as const),
        }));

  const browserRows = (browsers.data ?? []).filter((b) => b.detected || b.healthy);
  const browserNodes: HubNode[] =
    browserRows.length === 0
      ? [
          {
            key: "__none",
            name: t("overview.map_no_browsers"),
            meta: t("overview.map_no_browsers_meta"),
            lit: false,
            dim: true,
            edge: "off",
          },
        ]
      : browserRows.map((b) => ({
          key: b.key,
          name: browserDisplayName(b.key),
          meta: b.healthy ? t("overview.browser_registered") : t("overview.browser_unregistered"),
          lit: b.healthy && keyPresent,
          dim: !b.healthy,
          edge: b.healthy && keyPresent ? ("on" as const) : ("off" as const),
        }));

  const shownClients = collapseColumn(clientNodes, (n) => t("overview.map_more", [String(n)]));
  const shownBrowsers = collapseColumn(browserNodes, (n) => t("overview.map_more", [String(n)]));

  const laneH = Math.max(
    HOST_H,
    stackHeight(shownClients.length),
    stackHeight(shownBrowsers.length),
  );
  const clientYs = centers(shownClients.length, laneH);
  const browserYs = centers(shownBrowsers.length, laneH);

  const registered = (browsers.data ?? []).filter((b) => b.healthy).length;
  const hostMeta = keyPresent
    ? enclave.data?.policy?.enrolled === true
      ? t("overview.map_host_attested")
      : t("overview.map_host_key_only")
    : enclave.data?.key === "unsupported"
      ? t("enclave.key_unsupported")
      : t("overview.map_host_unenrolled");

  const headPill = engaged ? (
    <Pill tone="danger" dot>
      {t("overview.pill_kill")}
    </Pill>
  ) : keyPresent && registered > 0 && serving ? (
    <Pill tone="live" dot>
      {t("overview.pill_ok")}
    </Pill>
  ) : (
    <Pill dot>{t("overview.pill_partial")}</Pill>
  );

  return (
    <ViewShell
      title={t("nav.overview")}
      sub={t("overview.sub")}
      right={headPill}
      foot={
        status !== undefined && (
          <span className="foot-note tnum">
            chromium-bridge {status.version} - {status.os}/{status.arch}
          </span>
        )
      }
    >
      <div className="flex flex-col gap-2.5">
        {statusError !== undefined && <ErrorNote>{statusError}</ErrorNote>}
        {status?.hostError != null && <ErrorNote>{status.hostError}</ErrorNote>}
        {firstRunError !== undefined && <ErrorNote>{firstRunError}</ErrorNote>}
        {status !== undefined && status.kill.state === "unreadable" && (
          <div className="banner banner-danger">
            <span className="banner-text">
              {t("overview.kill_unreadable")} <span className="mono">{status.kill.detail}</span>
            </span>
          </div>
        )}

        {/* First launch: detection only; connecting stays an explicit click. */}
        {firstRun !== null && firstRun.detected.length > 0 && (
          <div className="banner">
            <span className="banner-text">
              {t("overview.first_run_detected", [formatBrowserList(firstRun.detected)])}
            </span>
            {(connectReport === undefined || connectReport.errors.length > 0) && (
              <Button
                size="sm"
                disabled={busy !== undefined}
                onClick={() => void connectAll(firstRun.detected)}
              >
                {busy === "connect-all" ? t("common.working") : t("overview.first_run_connect_all")}
              </Button>
            )}
          </div>
        )}
        {connectReport !== undefined && connectReport.lines.length > 0 && (
          <Mono>{connectReport.lines.join("\n")}</Mono>
        )}
        {connectReport !== undefined && connectReport.errors.length > 0 && (
          <ErrorNote>{connectReport.errors.join("\n")}</ErrorNote>
        )}

        {/* Trust map */}
        <section aria-label={t("overview.map_title")}>
          <div className="pipeline-head">
            <SpecLabel>{t("overview.map_title")}</SpecLabel>
            {status !== undefined && (
              <span className="pipeline-meta">
                {status.os}/{status.arch}
              </span>
            )}
          </div>
          <div className="hub">
            <span className="hub-col-label hub-clients tnum">
              {t("overview.map_clients", [String(clientRows.length)])}
            </span>
            <span className="hub-col-label hub-browsers tnum">
              {t("overview.map_browsers", [String(browserRows.length)])}
            </span>

            <div className="hub-stack hub-clients" style={{ height: laneH }}>
              {shownClients.map((n) => (
                <HubNodeBox key={n.key} node={n} />
              ))}
            </div>

            <Lane
              dir="in"
              height={laneH}
              edges={shownClients.map((n, i) => ({ y: clientYs[i] ?? 0, state: n.edge }))}
              label={t("overview.lane_stdio")}
            />

            <section
              className={`hub-host${keyPresent ? "" : " dim"}`}
              style={{ height: HOST_H }}
              aria-label={t("overview.map_host_role")}
            >
              <div className="gate-role">{t("overview.map_host_role")}</div>
              <div className="hub-node-name" style={{ fontSize: 14 }}>
                <Dot tone={engaged ? "down" : serving ? "live" : "idle"} />
                chromium-bridge
              </div>
              <div className="hub-node-meta">{hostMeta}</div>
              {fingerprint !== undefined && (
                <div className="gate-id">{formatFingerprint(fingerprint)}</div>
              )}
            </section>

            <Lane
              dir="out"
              height={laneH}
              edges={shownBrowsers.map((n, i) => ({ y: browserYs[i] ?? 0, state: n.edge }))}
              label={t("overview.lane_native")}
            />

            <div className="hub-stack hub-browsers" style={{ height: laneH }}>
              {shownBrowsers.map((n) => (
                <HubNodeBox key={n.key} node={n} />
              ))}
            </div>
          </div>
          <Consequence className="quiet mt-2">{t("overview.map_note")}</Consequence>
        </section>

        {/* Flat control rows: hairline rules and whitespace, no card chrome */}
        <div className="rows">
          <section className="row" aria-label={t("overview.kill_label")}>
            <span className="row-label">{t("overview.kill_label")}</span>
            <div className="row-main">
              <div className="row-status">
                {status === undefined ? (
                  t("common.loading")
                ) : engaged ? (
                  <StatusDot tone="down">{t("overview.kill_engaged")}</StatusDot>
                ) : killState === "off" ? (
                  t("overview.kill_off")
                ) : (
                  <StatusDot tone="down">{t("overview.kill_unreadable_state")}</StatusDot>
                )}
              </div>
              <Consequence>{t("overview.kill_consequence")}</Consequence>
              {releasedBy !== undefined && (
                <StatusDot tone="live" className="text-xs">
                  {t("overview.kill_released", [authLabel(releasedBy)])}
                </StatusDot>
              )}
              {actionError !== undefined && (
                <p className="mono m-0 text-[11px] text-danger">{actionError}</p>
              )}
            </div>
            <div className="row-side flex-col items-end gap-[5px]">
              {engaged ? (
                <Button gated disabled={busy !== undefined} onClick={() => setReleaseOpen(true)}>
                  {busy === "release" ? t("common.working") : t("overview.kill_release")}
                </Button>
              ) : (
                <Button
                  variant="danger"
                  disabled={busy !== undefined}
                  onClick={() => void engage()}
                >
                  {busy === "engage" ? t("common.working") : t("overview.kill_engage")}
                </Button>
              )}
              <span className="inline-flex items-center gap-[5px] text-[11px] text-text-3">
                {t("overview.kill_release_note")}
                <TouchIdChip />
              </span>
            </div>
          </section>

          <section className="row" aria-label={t("overview.server_label")}>
            <span className="row-label">{t("overview.server_label")}</span>
            <div className="row-main">
              <div className="row-status">
                {status === undefined ? (
                  t("common.loading")
                ) : status.server.lockError !== null ? (
                  <StatusDot tone="pending">
                    {t("overview.server_lock_unreadable", [status.server.lockError])}
                  </StatusDot>
                ) : !status.server.lockPresent ? (
                  <StatusDot tone="idle">{t("overview.server_not_running")}</StatusDot>
                ) : status.server.reachable === true ? (
                  <StatusDot tone="live">{t("overview.server_reachable")}</StatusDot>
                ) : (
                  <StatusDot tone="pending">{t("overview.server_unreachable")}</StatusDot>
                )}
              </div>
              <Consequence>{t("overview.server_consequence")}</Consequence>
            </div>
            <div className="row-side">
              {status?.server.pid != null && (
                <span className="row-count">
                  {t("overview.server_pid", [String(status.server.pid)])}
                </span>
              )}
              <ChipMono>{status?.server.endpoint ?? "com.vivswan.chromium_bridge.host"}</ChipMono>
            </div>
          </section>

          <section className="row" aria-label={t("overview.enclave_label")}>
            <span className="row-label">{t("overview.enclave_label")}</span>
            <div className="row-main">
              <div className="row-status">
                {enclave.error !== undefined ? (
                  <StatusDot tone="down">{t("enclave.key_error")}</StatusDot>
                ) : enclave.data === undefined ? (
                  t("common.loading")
                ) : (
                  <>
                    <StatusDot
                      tone={
                        enclave.data.key === "present"
                          ? "live"
                          : enclave.data.key === "none"
                            ? "idle"
                            : "down"
                      }
                    >
                      {enclave.data.key === "present"
                        ? t("enclave.key_present")
                        : enclave.data.key === "none"
                          ? t("enclave.key_none")
                          : enclave.data.key === "unsupported"
                            ? t("enclave.key_unsupported")
                            : enclave.data.key === "invalid"
                              ? t("enclave.key_invalid")
                              : t("enclave.key_error")}
                    </StatusDot>
                    {keyPresent && <TouchIdChip />}
                  </>
                )}
              </div>
            </div>
            <div className="row-side">
              {fingerprint !== undefined && <ChipMono>{formatFingerprint(fingerprint)}</ChipMono>}
            </div>
          </section>

          <section className="row" aria-label={t("nav.browsers")}>
            <span className="row-label">{t("nav.browsers")}</span>
            <div className="row-main">
              {browsers.error !== undefined ? (
                <p className="mono m-0 text-[11px] text-danger">{browsers.error}</p>
              ) : (
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                  {browserRows.length === 0 && (
                    <span className="text-text-3">{t("overview.map_no_browsers")}</span>
                  )}
                  {browserRows.map((b) => (
                    <span
                      key={b.key}
                      className={`inline-flex items-center gap-1.5 ${
                        b.healthy ? "text-text-2" : "text-text-3"
                      }`}
                    >
                      <Dot tone={b.healthy ? "live" : "idle"} />
                      {browserDisplayName(b.key)}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="row-side">
              <span className="row-count">
                {t("overview.browsers_count", [String(registered)])}
              </span>
            </div>
          </section>

          <section className="row" aria-label={t("nav.clients")}>
            <span className="row-label">{t("nav.clients")}</span>
            <div className="row-main">
              {clients.error !== undefined ? (
                <p className="mono m-0 text-[11px] text-danger">{clients.error}</p>
              ) : (
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                  {clientRows.length === 0 && (
                    <span className="text-text-3">{t("overview.map_no_clients")}</span>
                  )}
                  {clientRows.map((c) => (
                    <span key={c.name} className="inline-flex items-center gap-1.5 text-text-2">
                      <Dot tone={serving ? "live" : "idle"} />
                      {c.name}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <div className="row-side">
              <span className="row-count">
                {t("overview.clients_count", [String(clientRows.length)])}
              </span>
            </div>
          </section>
        </div>

        <ConfirmDialog
          open={releaseOpen}
          onOpenChange={setReleaseOpen}
          title={t("overview.kill_release_dialog_title")}
          body={t("overview.kill_release_dialog_body")}
          confirmLabel={t("overview.kill_release_confirm")}
          busy={busy === "release"}
          onConfirm={() => void confirmRelease()}
        />
      </div>
    </ViewShell>
  );
}
