import { useState } from "react";
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
import { api, errorText } from "@/lib/tauri";
import { useAppStore } from "@/store";

/* ------------------------------------------------------------------ */
/* Trust map: the fan-in/fan-out hub. Clients fan in to the host; the  */
/* host fans out to browsers. Empty-state vocabulary (first-run.html): */
/* ghost = exists on this machine, no trust established (dashed,       */
/* hollow); held = registered, waiting on the pairing ceremony         */
/* (amber). Green appears only once something is actually attested.    */
/* ------------------------------------------------------------------ */

type EdgeState = "on" | "idle" | "held" | "off";
type NodeVariant = "lit" | "held" | "ghost" | "dim" | "plain";

interface HubNode {
  key: string;
  name: string;
  meta: string;
  variant: NodeVariant;
  dot: "live" | "pending" | "down" | "idle";
  edge: EdgeState;
}

/** The five Overview lifecycle states (first-run.html section 4). One
 * leading element each; if a state is not in this list, it is not a state. */
type Lifecycle = "loading" | "fresh" | "connected" | "attested" | "killed";

const NODE_H = 56;
const NODE_GAP = 10;
const LANE_W = 80;
const HOST_H = 122;

/** Collapse rule for >3 nodes per column: keep the 3 highest-priority
 * nodes (lit > held > plain > ghost/dim), then one dim "+N more" node
 * whose single dashed edge merges the rest. */
function collapseColumn(nodes: HubNode[], moreLabel: (n: number) => string): HubNode[] {
  if (nodes.length <= 4) return nodes;
  const rank = (n: HubNode) =>
    n.variant === "lit" ? 0 : n.variant === "held" ? 1 : n.variant === "plain" ? 2 : 3;
  const kept = [...nodes].sort((a, b) => rank(a) - rank(b)).slice(0, 3);
  const shown = nodes.filter((n) => kept.includes(n));
  const rest = nodes.length - shown.length;
  shown.push({
    key: "__more",
    name: moreLabel(rest),
    meta: "",
    variant: "dim",
    dot: "idle",
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
  const focus = edges.find((e) => e.state === "on") ?? edges.find((e) => e.state === "held");
  const labelTop =
    dir === "in"
      ? hostY + 9
      : focus !== undefined
        ? Math.min(Math.max(focus.y - 26, 2), height - 18)
        : hostY - 9;
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
          const cls = { on: "edge-on", idle: "edge-idle", held: "edge-held", off: "edge-off" }[
            state
          ];
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
              {state === "held" && dir === "out" && (
                <circle cx="77" cy={y} r="1.8" fill="var(--pending)" />
              )}
            </g>
          );
        })}
      </svg>
      <span className="hub-lane-label" style={{ top: labelTop }}>
        {label}
      </span>
    </div>
  );
}

function HubNodeBox({ node }: { node: HubNode }) {
  const variantClass = node.variant === "plain" ? "" : ` ${node.variant}`;
  return (
    <div className={`hub-node${variantClass}`}>
      <div className="hub-node-name">
        <Dot tone={node.dot} />
        {node.name}
      </div>
      {node.meta !== "" && <div className="hub-node-meta">{node.meta}</div>}
    </div>
  );
}

/** brave://extensions and friends; chrome:// is the family default. */
function extensionsUrl(browserKey: string): string {
  const scheme = ["brave", "edge", "vivaldi", "opera"].includes(browserKey) ? browserKey : "chrome";
  return `${scheme}://extensions`;
}

/* ------------------------------------------------------------------ */

export function OverviewView() {
  const { t } = useI18n();
  const status = useAppStore((s) => s.status);
  const statusError = useAppStore((s) => s.statusError);
  const refreshStatus = useAppStore((s) => s.refreshStatus);
  const setView = useAppStore((s) => s.setView);
  const browsers = useAsync(api.browsersList);
  const enclave = useAsync(api.enclaveStatus);
  const clients = useAsync(api.clientsList);
  const extension = useAsync(api.extensionInfo);

  const [busy, setBusy] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [connectReport, setConnectReport] = useState<string>();
  const [releaseOpen, setReleaseOpen] = useState(false);
  const [releasedBy, setReleasedBy] = useState<string>();

  // Registration is opt-in (ADR-0029): the guide only ever registers the
  // browser whose Connect the user clicked. Sequential for "Connect both";
  // the registrations share the install dir.
  const connect = async (keys: string[]) => {
    setBusy("connect");
    setActionError(undefined);
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
    if (lines.length > 0) setConnectReport(lines.join("\n"));
    if (errors.length > 0) setActionError(errors.join("\n"));
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

  /* ----- lifecycle ----- */

  const killState = status?.kill.state;
  const engaged = killState === "engaged";
  // "serving" is only claimed when the kill state is provably off AND the
  // server socket answered; loading or unreadable never counts as off.
  const serving = status?.server.reachable === true && killState === "off";
  const keyPresent = enclave.data?.key === "present";
  const fingerprint = enclave.data?.fingerprint;

  const clientRows = clients.data?.clients ?? [];
  // a registration that exists on disk stays visible even when its browser
  // is no longer detected - a leftover manifest is never a fresh install
  const browserRows = (browsers.data ?? []).filter(
    (b) => b.detected || b.healthy || b.code !== "missing",
  );
  const registeredRows = browserRows.filter((b) => b.healthy);
  // absent registration vs a present-but-wrong one (stale/foreign/unreadable):
  // the latter is never "fresh" and offers Repair, not Connect
  const missingRows = browserRows.filter((b) => !b.healthy && b.code === "missing");
  const brokenRows = browserRows.filter((b) => !b.healthy && b.code !== "missing");
  const registered = registeredRows.length;

  const lifecycle: Lifecycle = engaged
    ? "killed"
    : status === undefined || browsers.data === undefined || clients.data === undefined
      ? "loading"
      : clientRows.length > 0
        ? "attested"
        : registered > 0 || brokenRows.length > 0
          ? "connected"
          : "fresh";
  const guide = lifecycle === "fresh" || lifecycle === "connected";

  /* ----- derive the map ----- */

  const clientNodes: HubNode[] =
    clientRows.length === 0
      ? [
          {
            key: "__ghost",
            name: t("overview.ghost_client"),
            meta: t("overview.ghost_client_meta"),
            variant: "ghost",
            dot: "idle",
            edge: "off",
          },
        ]
      : clientRows.map((c) => ({
          key: c.name,
          name: c.name,
          meta: t("overview.client_paired", [new Date(c.addedUnix * 1000).toLocaleDateString()]),
          variant: serving ? ("lit" as const) : ("plain" as const),
          dot: serving ? ("live" as const) : ("idle" as const),
          edge: serving ? ("on" as const) : ("idle" as const),
        }));

  const browserNodes: HubNode[] =
    browserRows.length === 0
      ? [
          {
            key: "__ghost",
            name: t("overview.map_no_browsers"),
            meta: t("overview.map_no_browsers_meta"),
            variant: "ghost",
            dot: "idle",
            edge: "off",
          },
        ]
      : browserRows.map((b) => {
          if (!b.healthy) {
            if (b.code !== "missing") {
              // a manifest exists but is wrong: amber node, real state text
              return {
                key: b.key,
                name: browserDisplayName(b.key),
                meta: b.state,
                variant: "held" as const,
                dot: "pending" as const,
                edge: "off" as const,
              };
            }
            return {
              key: b.key,
              name: browserDisplayName(b.key),
              meta: t("overview.node_ghost_meta"),
              variant: "ghost" as const,
              dot: "idle" as const,
              edge: "off" as const,
            };
          }
          if (lifecycle === "attested" && keyPresent) {
            return {
              key: b.key,
              name: browserDisplayName(b.key),
              meta: t("overview.browser_registered"),
              variant: "lit" as const,
              dot: "live" as const,
              edge: "on" as const,
            };
          }
          if (lifecycle === "killed") {
            return {
              key: b.key,
              name: browserDisplayName(b.key),
              meta: t("overview.browser_registered"),
              variant: "plain" as const,
              dot: "idle" as const,
              edge: "off" as const,
            };
          }
          // registered but the pairing ceremony is still owed: amber
          return {
            key: b.key,
            name: browserDisplayName(b.key),
            meta: t("overview.node_held_meta"),
            variant: "held" as const,
            dot: "pending" as const,
            edge: "held" as const,
          };
        });

  const shownClients = collapseColumn(clientNodes, (n) => t("overview.map_more", [String(n)]));
  const shownBrowsers = collapseColumn(browserNodes, (n) => t("overview.map_more", [String(n)]));

  const laneH = Math.max(
    HOST_H,
    stackHeight(shownClients.length),
    stackHeight(shownBrowsers.length),
  );
  const clientYs = centers(shownClients.length, laneH);
  const browserYs = centers(shownBrowsers.length, laneH);

  // the host earns its green border only once something is attested; on a
  // fresh install the only green on screen is its own liveness dot. An
  // unknown kill state claims nothing; unreadable renders down (fail closed).
  const hostLit = lifecycle === "attested" && keyPresent;
  const hostDot: "live" | "down" | "idle" =
    killState === undefined ? "idle" : killState !== "off" ? "down" : "live";
  const hostMeta =
    enclave.error !== undefined
      ? t("enclave.key_error")
      : enclave.data === undefined
        ? t("common.loading")
        : enclave.data.key === "unsupported"
          ? t("enclave.key_unsupported")
          : guide
            ? keyPresent
              ? t("overview.map_host_running_key")
              : t("overview.map_host_running_nokey")
            : keyPresent
              ? enclave.data.policy?.enrolled === true
                ? t("overview.map_host_attested")
                : t("overview.map_host_key_only")
              : t("overview.map_host_unenrolled");

  const laneInLabel =
    lifecycle === "killed"
      ? t("overview.lane_severed")
      : clientRows.length === 0
        ? t("overview.lane_stdio_none")
        : t("overview.lane_stdio");
  const laneOutLabel =
    lifecycle === "killed"
      ? t("overview.lane_severed")
      : lifecycle === "attested"
        ? t("overview.lane_native")
        : registered > 0
          ? t("overview.lane_native_held")
          : t("overview.lane_native_none");

  const browsersColLabel =
    lifecycle === "fresh"
      ? t("overview.map_browsers_detected", [String(browserRows.length)])
      : lifecycle === "connected"
        ? t("overview.map_browsers_partial", [String(registered), String(browserRows.length)])
        : t("overview.map_browsers", [String(browserRows.length)]);

  const headSub =
    lifecycle === "fresh"
      ? t("overview.sub_fresh")
      : lifecycle === "connected"
        ? registered > 0
          ? t("overview.sub_connected", [formatBrowserList(registeredRows.map((b) => b.key))])
          : t("overview.sub_repair")
        : t("overview.sub");

  const headPill =
    lifecycle === "killed" ? (
      <Pill tone="danger" dot>
        {t("overview.pill_kill")}
      </Pill>
    ) : lifecycle === "fresh" ? (
      <Pill dot>{t("overview.pill_fresh")}</Pill>
    ) : lifecycle === "connected" ? (
      <Pill tone="pending" dot>
        {brokenRows.length > 0 ? t("overview.pill_repair") : t("overview.pill_steps", ["2"])}
      </Pill>
    ) : keyPresent && registered > 0 && serving ? (
      <Pill tone="live" dot>
        {t("overview.pill_ok")}
      </Pill>
    ) : (
      <Pill dot>{t("overview.pill_partial")}</Pill>
    );

  /* ----- shared fragments ----- */

  const killRow = (
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
      </div>
      <div className="row-side flex-col items-end gap-[5px]">
        {engaged ? (
          <Button gated disabled={busy !== undefined} onClick={() => setReleaseOpen(true)}>
            {busy === "release" ? t("common.working") : t("overview.kill_release")}
          </Button>
        ) : (
          <Button variant="danger" disabled={busy !== undefined} onClick={() => void engage()}>
            {busy === "engage" ? t("common.working") : t("overview.kill_engage")}
          </Button>
        )}
        <span className="inline-flex items-center gap-[5px] text-[11px] text-text-3">
          {t("overview.kill_release_note")}
          <TouchIdChip />
        </span>
      </div>
    </section>
  );

  const trustMap = (
    <section aria-label={t("overview.map_title")}>
      <div className="pipeline-head">
        <SpecLabel>{t("overview.map_title")}</SpecLabel>
        <span className="pipeline-meta">
          {lifecycle === "killed"
            ? t("overview.map_meta_killed")
            : guide
              ? t("overview.map_meta_none")
              : status !== undefined
                ? `${status.os}/${status.arch}`
                : ""}
        </span>
      </div>
      <div className="hub">
        <span className="hub-col-label hub-clients tnum">
          {t("overview.map_clients", [String(clientRows.length)])}
        </span>
        <span className="hub-col-label hub-browsers tnum">{browsersColLabel}</span>

        <div className="hub-stack hub-clients" style={{ height: laneH }}>
          {shownClients.map((n) => (
            <HubNodeBox key={n.key} node={n} />
          ))}
        </div>

        <Lane
          dir="in"
          height={laneH}
          edges={shownClients.map((n, i) => ({
            y: clientYs[i] ?? 0,
            state: lifecycle === "killed" ? "off" : n.edge,
          }))}
          label={laneInLabel}
        />

        <section
          className={`hub-host${hostLit ? "" : " dim"}`}
          style={{ height: HOST_H }}
          aria-label={t("overview.map_host_role")}
        >
          <div className="gate-role">{t("overview.map_host_role")}</div>
          <div className="hub-node-name" style={{ fontSize: 14 }}>
            <Dot tone={hostDot} />
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
          edges={shownBrowsers.map((n, i) => ({
            y: browserYs[i] ?? 0,
            state: lifecycle === "killed" ? "off" : n.edge,
          }))}
          label={laneOutLabel}
        />

        <div className="hub-stack hub-browsers" style={{ height: laneH }}>
          {shownBrowsers.map((n) => (
            <HubNodeBox key={n.key} node={n} />
          ))}
        </div>
      </div>
      {!guide && <Consequence className="quiet mt-2">{t("overview.map_note")}</Consequence>}
    </section>
  );

  /* ----- the first-steps guide (fresh + connected states) ----- */

  const firstRegistered = registeredRows[0];
  const guideFlow = (
    <ol className="flow mt-[18px] max-w-none">
      {/* step 1: connect a browser */}
      <li className={`flow-step ${registered > 0 ? "done" : "next"}`}>
        <span className="flow-mark" aria-hidden="true">
          {registered === 0 ? (
            "1"
          ) : (
            <svg width="10" height="10" viewBox="0 0 12 12" fill="none" aria-hidden="true">
              <path
                d="M2.5 6.5 5 9l4.5-6"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          )}
        </span>
        <div>
          <div className="flow-title">
            {t("overview.guide_step1_title")}
            <span className="flow-state">
              {registered === 0 ? t("overview.guide_state_start") : t("setup.state_done")}
            </span>
          </div>
          {registered === 0 ? (
            <>
              <p className="flow-body">
                {missingRows.length === 0 && brokenRows.length === 0
                  ? t("overview.guide_step1_none")
                  : brokenRows.length > 0
                    ? t("overview.guide_step1_body_repair")
                    : t("overview.guide_step1_body")}
              </p>
              <div className="detect">
                {[...brokenRows, ...missingRows].map((b) => (
                  <div className="detect-row" key={b.key}>
                    <span>
                      <span className="detect-name">{browserDisplayName(b.key)}</span>{" "}
                      <span className="detect-meta">
                        {b.code === "missing" ? t("browsers.detected") : b.state}
                      </span>
                    </span>
                    <Button
                      size="sm"
                      disabled={busy !== undefined}
                      onClick={() => void connect([b.key])}
                    >
                      {busy === "connect"
                        ? t("common.working")
                        : b.code === "missing"
                          ? t("browsers.connect")
                          : t("browsers.repair")}
                    </Button>
                  </div>
                ))}
                <div className="detect-row">
                  <span className="detect-meta">
                    {t("overview.guide_custom")}{" "}
                    <button type="button" className="linkish" onClick={() => setView("browsers")}>
                      {t("browsers.custom_title")}
                    </button>
                  </span>
                  {missingRows.length > 1 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={busy !== undefined}
                      onClick={() => void connect(missingRows.map((b) => b.key))}
                    >
                      {t("overview.guide_connect_all")}
                    </Button>
                  )}
                </div>
              </div>
              <Consequence>
                {t("overview.guide_connect_consequence")} <strong>{t("nav.browsers")}</strong>.
              </Consequence>
            </>
          ) : (
            <>
              <p className="flow-body">
                {t("overview.guide_step1_done", [
                  formatBrowserList(registeredRows.map((b) => b.key)),
                ])}{" "}
                <button type="button" className="linkish" onClick={() => setView("browsers")}>
                  {t("nav.browsers")}
                </button>
                .
              </p>
              {/* a healthy registration never hides a broken one */}
              {brokenRows.length > 0 && (
                <div className="detect">
                  {brokenRows.map((b) => (
                    <div className="detect-row" key={b.key}>
                      <span>
                        <span className="detect-name">{browserDisplayName(b.key)}</span>{" "}
                        <span className="detect-meta">{b.state}</span>
                      </span>
                      <Button
                        size="sm"
                        disabled={busy !== undefined}
                        onClick={() => void connect([b.key])}
                      >
                        {busy === "connect" ? t("common.working") : t("browsers.repair")}
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </li>

      {/* step 2: load the extension */}
      <li className={`flow-step${registered > 0 ? " next" : ""}`}>
        <span className="flow-mark" aria-hidden="true">
          2
        </span>
        <div>
          <div className="flow-title">
            {t("setup.step2_title")}
            <span className="flow-state">
              {registered > 0 ? t("setup.state_next") : t("overview.guide_state_waits")}
            </span>
          </div>
          {firstRegistered !== undefined ? (
            <>
              <p className="flow-body">
                {t("overview.guide_step2_restart", [browserDisplayName(firstRegistered.key)])}{" "}
                <span className="mono">{extensionsUrl(firstRegistered.key)}</span>,{" "}
                <strong>{t("setup.step2_a_dev")}</strong>, <strong>{t("setup.step2_b_btn")}</strong>
                :
              </p>
              <div className="mt-[7px] flex items-center gap-2">
                {extension.data?.path != null ? (
                  <>
                    <ChipMono wrap>{extension.data.path}</ChipMono>
                    <Button
                      size="sm"
                      className="flex-none"
                      onClick={() =>
                        void api.extensionReveal().catch((err: unknown) => {
                          setActionError(errorText(err));
                        })
                      }
                    >
                      {t("setup.ext_reveal")}
                    </Button>
                  </>
                ) : extension.error !== undefined ? (
                  <span className="mono text-[11px] text-danger">{extension.error}</span>
                ) : extension.data !== undefined ? (
                  <span className="text-xs text-danger">{t("setup.ext_missing")}</span>
                ) : (
                  <span className="text-xs text-text-3">{t("common.loading")}</span>
                )}
              </div>
              <p className="flow-body mt-[7px]">{t("overview.guide_step2_code")}</p>
            </>
          ) : (
            <p className="flow-body">
              {t("overview.guide_step2_waits_1")}{" "}
              <button type="button" className="linkish" onClick={() => setView("setup")}>
                {t("nav.setup")}
              </button>{" "}
              {t("overview.guide_step2_waits_2")}
            </p>
          )}
        </div>
      </li>

      {/* step 3: connect the MCP client */}
      <li className="flow-step">
        <span className="flow-mark" aria-hidden="true">
          3
        </span>
        <div>
          <div className="flow-title">
            {t("setup.step3_title")}
            <span className="flow-state">
              {registered > 0 ? t("overview.guide_state_after") : t("overview.guide_state_waits")}
            </span>
          </div>
          {registered > 0 ? (
            <p className="flow-body">
              {t("overview.guide_step3_after_1")}{" "}
              <button type="button" className="linkish" onClick={() => setView("setup")}>
                {t("nav.setup")}
              </button>
              {t("overview.guide_step3_after_2")}
            </p>
          ) : (
            <p className="flow-body">{t("overview.guide_step3_waits")}</p>
          )}
        </div>
      </li>
    </ol>
  );

  /* ----- control rows (attested + killed states) ----- */

  const controlRows = (
    <div className="rows">
      {lifecycle !== "killed" && killRow}
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
          <ChipMono wrap>{status?.server.endpoint ?? "com.vivswan.chromium_bridge.host"}</ChipMono>
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
          {fingerprint !== undefined && <ChipMono wrap>{formatFingerprint(fingerprint)}</ChipMono>}
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
          <span className="row-count">{t("overview.browsers_count", [String(registered)])}</span>
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
  );

  return (
    <ViewShell
      title={t("nav.overview")}
      sub={headSub}
      right={headPill}
      foot={
        <>
          {status !== undefined && (
            <span className="foot-note tnum">
              chromium-bridge {status.version} - {status.os}/{status.arch}
            </span>
          )}
          {lifecycle === "fresh" && <span className="foot-note">{t("overview.foot_fresh")}</span>}
        </>
      }
    >
      <div className="flex flex-col gap-2.5">
        {statusError !== undefined && <ErrorNote>{statusError}</ErrorNote>}
        {status?.hostError != null && <ErrorNote>{status.hostError}</ErrorNote>}
        {enclave.error !== undefined && <ErrorNote>{enclave.error}</ErrorNote>}
        {browsers.error !== undefined && <ErrorNote>{browsers.error}</ErrorNote>}
        {clients.error !== undefined && <ErrorNote>{clients.error}</ErrorNote>}
        {actionError !== undefined && <ErrorNote>{actionError}</ErrorNote>}
        {status !== undefined && status.kill.state === "unreadable" && (
          <div className="banner banner-danger">
            <span className="banner-text">
              {t("overview.kill_unreadable")} <span className="mono">{status.kill.detail}</span>
            </span>
          </div>
        )}

        {/* killed: the kill row leads in red; everything else recedes */}
        {lifecycle === "killed" && <div className="rows mt-0">{killRow}</div>}

        {lifecycle === "loading" ? (
          <p className="m-0 text-xs text-text-3">{t("common.loading")}</p>
        ) : (
          trustMap
        )}

        {connectReport !== undefined && <Mono>{connectReport}</Mono>}

        {guide && guideFlow}
        {(lifecycle === "attested" || lifecycle === "killed") && controlRows}

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
