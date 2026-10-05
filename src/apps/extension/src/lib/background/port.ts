// Native-messaging port lifecycle. MV3 service workers are killed ~every 5 min
// and Chrome kills the host process whenever the port closes, so we reconnect
// automatically on startup and after any disconnect.

import { parseBridgeReq } from "@chromium-bridge/shared/envelope";
import { NATIVE_HOST_ID } from "@chromium-bridge/shared/identity.gen";
import { unreachable } from "@chromium-bridge/shared/util";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { inLife } from "../shared/in-life";
import { maskErrorMessage } from "../shared/masking";
import * as webauthn from "../webauthn/exchange";
import * as auditLog from "./audit-log";
import * as clients from "./clients";
import * as presence from "./confirm/presence";
import type { Connection, PortCollaborator } from "./connection";
import { collaborator as cancelSignals, dispatch } from "./dispatch";
import * as enrollment from "./enrollment";
import * as hostAdmin from "./host-admin";
import * as kill from "./kill";
import * as policySync from "./policy-sync";

export const collaborators: readonly PortCollaborator[] = [
  enrollment.collaborator,
  clients.collaborator,
  hostAdmin.collaborator,
  kill.collaborator,
  auditLog.collaborator,
  presence.collaborator,
  policySync.collaborator,
  webauthn.collaborator,
  cancelSignals,
];

// The native link is in exactly one of these states. One value, not a
// port/flag/timer trio: a nullable port beside a boolean could contradict
// (a re-entrant connect that threw used to leave the OLD port assigned
// while isNativeConnected() reported disconnected), and every transition
// below consumes the previous state, so a replaced port can never linger
// behind a state that reads down.
type NativeLink =
  | { state: "connected"; port: Browser.runtime.Port; conn: Connection }
  | { state: "reconnect-scheduled"; timer: ReturnType<typeof setTimeout> }
  | { state: "down" };

const link = inLife<NativeLink>(() => ({ state: "down" }));
const connects = inLife(() => 0);

export function isNativeConnected(): boolean {
  return link.value.state === "connected";
}

/** The currency contract is stated on Connection in connection.ts. */
function isLive(conn: Connection): boolean {
  return link.value.state === "connected" && link.value.conn === conn;
}

/** Consume the current link and leave it down: cancel a scheduled
 * reconnect, or tear a held port down together with everything bound to it.
 * The one place a link is torn down, so no path can orphan a live port - or
 * a collaborator attachment that would still honor its frames - behind a
 * state that reads down. */
function teardownLink(): void {
  const prev = link.value;
  link.value = { state: "down" };
  if (prev.state === "reconnect-scheduled") clearTimeout(prev.timer);
  if (prev.state === "connected") {
    // Detach in the same synchronous transition that consumes the port. Left
    // attached, a frame Chrome already queued on the old port could still
    // reach a surface that acts on it (a presence proof approving a
    // confirmation while the link reads down).
    for (const c of collaborators) c.onDetach();
    try {
      prev.port.disconnect();
    } catch {
      // Already gone; the goal (no live orphan) holds either way.
    }
  }
}

export function connectNative() {
  // Consume whatever the link was first: a re-entrant connect must not
  // leave the previous port alive (its later onDisconnect would otherwise
  // race the fresh one) or a reconnect timer armed.
  teardownLink();
  try {
    const port = browser.runtime.connectNative(NATIVE_HOST_ID);
    const conn = mintConnection(port);
    link.value = { state: "connected", port, conn };
    console.log("[bb] native host connected", conn.generation);
    port.onMessage.addListener((msg) => onNativeMessage(conn, msg));
    port.onDisconnect.addListener(() => onNativeDisconnect(conn));
    for (const c of collaborators) c.onAttach(conn);
    // Pull the kill state on every connect: this is what clears a stale
    // "killed" mirror after a CLI unkill that happened while the SW slept
    // (the host pushes transitions and bad startup states, but the alive
    // direction is deliberately pull-based). The reply routes through the
    // kill collaborator like any other kill_status_result. Enrollment then
    // decides whether this connect needs a pairing challenge or a pending
    // host-key deletion.
    void kill.requestKillStatus();
    void enrollment.onPortConnected();
  } catch (e) {
    teardownLink();
    console.error("[bb] connectNative threw", e);
    scheduleReconnect();
  }
}

/** post is bound to this exact port; currency per Connection in connection.ts. */
function mintConnection(port: Browser.runtime.Port): Connection {
  const conn: Connection = {
    generation: ++connects.value,
    post(frame) {
      if (!isLive(conn)) return false;
      try {
        port.postMessage(frame);
        return true;
      } catch (e) {
        console.warn("[bb] post failed", e);
        return false;
      }
    },
  };
  return conn;
}

function onNativeDisconnect(conn: Connection) {
  // Only the CURRENT connection may take the link down: the disconnect of a
  // port a re-entrant connect already replaced must not tear down the live one.
  if (!isLive(conn)) return;
  teardownLink();
  const err = browser.runtime.lastError;
  console.warn("[bb] native host disconnected:", err?.message || "unknown");
  // Chrome kills the host process when the Port drops. Reconnect so a fresh
  // host is spawned - but back off to avoid a tight loop if the host is
  // genuinely unavailable (e.g. install not finished).
  scheduleReconnect();
}

function scheduleReconnect() {
  if (link.value.state !== "down") return;
  link.value = {
    state: "reconnect-scheduled",
    timer: setTimeout(() => {
      connectNative();
    }, 2000),
  };
}

function onNativeMessage(conn: Connection, msg: unknown) {
  // Same identity gate as the disconnect path: a frame from a connection this
  // link no longer holds (a re-entrant connect consumed it) is dropped before
  // the demux, so nothing queued on a dead port can reach a surface that
  // would act on it.
  if (!isLive(conn)) {
    console.warn("[bb] dropping frame from a stale native port");
    return;
  }
  // Control frames (ceremony, admin results, kill state, presence answers,
  // policy pushes) carry `type`, not `op`, and go to the one collaborator
  // that claims them BEFORE the request parse and the gates below: a killed
  // or unenrolled bridge still consumes pushes, and the dispatch barrier the
  // policy pushes feed must be able to open on the very connection it gates.
  for (const c of collaborators) {
    if (c.onFrame?.(msg)) return;
  }
  // Everything else must be a well-formed BridgeReq: envelope shape, a known
  // op, and args that satisfy that op's validator (see parseBridgeReq). This
  // crosses the native-messaging boundary, so anything malformed is refused
  // here - answered when an id can be correlated, dropped otherwise.
  const parsed = parseBridgeReq(msg);
  if (!parsed.ok) {
    console.warn("[bb] refusing bridge request:", parsed.error);
    if (parsed.id !== undefined) sendResponse(conn, parsed.id, false, undefined, parsed.error);
    return;
  }
  const req = parsed.req;
  // Fail closed: while enrollment is required and unsatisfied, every bridge request is refused and its op
  // never starts. dispatch.ts owns the request from here: it registers the id for a server `cancel` at once,
  // runs the gate, starts the op inside the gate's serialized critical section (a revoke or compromise mark
  // can never land between "gate said allowed" and the op), and resolves one outcome. A cancelled request
  // posts nothing: the server stopped waiting for that id. dispatch never rejects, so nothing is dropped here.
  void dispatch(req, enrollment.enrollmentGate).then((done) => {
    switch (done.outcome) {
      case "ok":
        sendResponse(conn, req.id, true, done.data);
        break;
      case "error":
        // A failure message can embed page-derived data (a CDP evaluate exception carries the page's error
        // description), so this egress is masked like any other.
        sendResponse(conn, req.id, false, undefined, maskErrorMessage(done.error));
        break;
      case "cancelled":
        break;
      default:
        unreachable(done);
    }
  });
}

/** A response rides the connection its request arrived on. Chrome spawns a fresh host per port, so once that
 * connection is replaced the host that asked is gone and Connection.post drops the reply instead of handing a
 * stranger an id it never issued. */
function sendResponse(
  conn: Connection,
  id: number | string,
  ok: boolean,
  data?: unknown,
  error?: string,
) {
  conn.post({ id, ok, data, error: ok ? undefined : error });
}
