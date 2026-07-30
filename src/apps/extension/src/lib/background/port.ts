// Native-messaging port lifecycle. MV3 service workers are killed ~every 5 min
// and Chrome kills the host process whenever the port closes, so we reconnect
// automatically on startup and after any disconnect.

import { NATIVE_HOST_ID, parseBridgeReq } from "@chromium-bridge/shared";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { maskErrorMessage } from "../shared/masking";
import * as auditLog from "./audit-log";
import * as clients from "./clients";
import * as presence from "./confirm/presence";
import { dispatch } from "./dispatch";
import {
  attachPort,
  detachPort,
  enrollmentGate,
  handleEnclaveFrame,
  isEnclaveFrame,
  onPortConnected,
} from "./enrollment";
import * as kill from "./kill";

// The native link is in exactly one of these states. One value, not a
// port/flag/timer trio: a nullable port beside a boolean could contradict
// (a re-entrant connect that threw used to leave the OLD port assigned
// while isNativeConnected() reported disconnected), and every transition
// below consumes the previous state, so a replaced port can never linger
// behind a state that reads down.
type NativeLink =
  | { state: "connected"; port: Browser.runtime.Port }
  | { state: "reconnect-scheduled"; timer: ReturnType<typeof setTimeout> }
  | { state: "down" };

let link: NativeLink = { state: "down" };

export function isNativeConnected(): boolean {
  return link.state === "connected";
}

/** Consume the current link and leave it down: cancel a scheduled
 * reconnect, or tear a held port down together with everything bound to it.
 * The one place a link is torn down, so no path can orphan a live port - or
 * a collaborator attachment that would still honor its frames - behind a
 * state that reads down. */
function teardownLink(): void {
  const prev = link;
  link = { state: "down" };
  if (prev.state === "reconnect-scheduled") clearTimeout(prev.timer);
  if (prev.state === "connected") {
    // The collaborator attachments belong to the port being consumed:
    // detach them in the same synchronous transition. Left attached, a
    // frame Chrome already queued on the old port could still reach a
    // surface that acts on it (a presence proof approving a confirmation
    // while the link reads down).
    detachPort();
    clients.detachPort();
    kill.detachPort();
    auditLog.detachPort();
    presence.detachPort();
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
    link = { state: "connected", port };
    console.log("[bb] native host connected");
    port.onMessage.addListener((msg) => onNativeMessage(port, msg));
    port.onDisconnect.addListener(onNativeDisconnect);
    // Hand the enrollment ceremony (ADR-0021), the trusted-client admin
    // exchange (ADR-0025), the kill-switch/audit surfaces (ADR-0030), and
    // the per-action presence gate (ADR-0031) the fresh port. Enrollment
    // decides whether this connect needs a pairing challenge or a pending
    // host-key deletion.
    attachPort(postFrame);
    clients.attachPort(postFrame);
    kill.attachPort(postFrame);
    auditLog.attachPort(postFrame);
    presence.attachPort(postFrame);
    // Pull the kill state on every connect (ADR-0030): this is what clears a
    // stale "killed" mirror after a CLI unkill that happened while the SW
    // slept (the host pushes transitions and bad startup states, but the
    // alive direction is deliberately pull-based). The result routes through
    // handleKillFrame like any other kill_status_result.
    void kill.requestKillStatus();
    void onPortConnected();
  } catch (e) {
    teardownLink();
    console.error("[bb] connectNative threw", e);
    scheduleReconnect();
  }
}

// Raw frame sender for enclave control frames (they are not BridgeResps).
function postFrame(frame: object): boolean {
  if (link.state !== "connected") return false;
  try {
    link.port.postMessage(frame);
    return true;
  } catch (e) {
    console.warn("[bb] postFrame failed", e);
    return false;
  }
}

function onNativeDisconnect(p: Browser.runtime.Port) {
  // Only the CURRENT port may take the link down: the disconnect of a port
  // a re-entrant connect already replaced must not tear down the live one.
  if (link.state !== "connected" || link.port !== p) return;
  teardownLink();
  const err = browser.runtime.lastError;
  console.warn("[bb] native host disconnected:", err?.message || "unknown");
  // Chrome kills the host process when the Port drops. Reconnect so a fresh
  // host is spawned - but back off to avoid a tight loop if the host is
  // genuinely unavailable (e.g. install not finished).
  scheduleReconnect();
}

function scheduleReconnect() {
  if (link.state !== "down") return;
  link = {
    state: "reconnect-scheduled",
    timer: setTimeout(() => {
      connectNative();
    }, 2000),
  };
}

function onNativeMessage(p: Browser.runtime.Port, msg: unknown) {
  // Same identity gate as the disconnect path: a frame from a port this
  // link no longer holds (a re-entrant connect consumed it) is dropped
  // before the demux, so nothing queued on a dead port can reach a surface
  // that would act on it.
  if (link.state !== "connected" || link.port !== p) {
    console.warn("[bb] dropping frame from a stale native port");
    return;
  }
  // Enclave control frames (ADR-0021/0025) are ceremony traffic between the
  // extension and the host itself; they carry `type`, not `op`, and are never
  // dispatched as bridge ops.
  if (isEnclaveFrame(msg)) {
    void handleEnclaveFrame(msg);
    return;
  }
  // Trusted-client admin results (ADR-0025), correlated back to the options
  // page's outstanding request. Same trust posture as the enclave frames.
  if (clients.isAdminFrame(msg)) {
    clients.handleAdminFrame(msg);
    return;
  }
  // Kill-switch state (ADR-0030): the reply to a kill control frame, or the
  // host's unsolicited startup/transition push. Either way it updates the
  // SW-only mirror the request gate reads.
  if (kill.isKillStatusFrame(msg)) {
    void kill.handleKillFrame(msg);
    return;
  }
  // Per-action presence answers (ADR-0031): the signed approval (or refusal)
  // for the confirmation round the presence provider has outstanding.
  if (presence.isPresenceFrame(msg)) {
    presence.handlePresenceFrame(msg);
    return;
  }
  // Everything else must be a well-formed BridgeReq: envelope shape, a known
  // op, and args that satisfy that op's validator (see parseBridgeReq). This
  // crosses the native-messaging boundary, so anything malformed is refused
  // here - answered when an id can be correlated, dropped otherwise.
  const parsed = parseBridgeReq(msg);
  if (!parsed.ok) {
    console.warn("[bb] refusing bridge request:", parsed.error);
    if (parsed.id !== undefined) sendResponse(parsed.id, false, undefined, parsed.error);
    return;
  }
  const req = parsed.req;
  // Fail closed (ADR-0021): while enrollment is required and unsatisfied,
  // every bridge request is refused right here and never reaches dispatch().
  // The dispatch kickoff is passed INTO the gate so it starts inside the
  // gate's serialized critical section: a revoke or compromise mark can then
  // never land between "gate said allowed" and "dispatch began".
  enrollmentGate(() => {
    dispatch(req).then(
      (data) => sendResponse(req.id, true, data),
      // A rejection message can embed page-derived data (a CDP evaluate
      // exception carries the page's error description), so this egress is
      // masked like any other.
      (err) => sendResponse(req.id, false, undefined, maskErrorMessage(err)),
    );
  }).then(
    (gate) => {
      if (!gate.allowed) sendResponse(req.id, false, undefined, gate.reason);
    },
    // Gate errors are ambiguity, and ambiguity refuses.
    (err) => sendResponse(req.id, false, undefined, `enrollment gate error: ${String(err)}`),
  );
}

function sendResponse(id: number | string, ok: boolean, data?: unknown, error?: string) {
  if (link.state !== "connected") return; // host gone; nothing to do
  try {
    link.port.postMessage({ id, ok, data, error: ok ? undefined : error });
  } catch (e) {
    // Port likely closed; the disconnect handler will reconnect.
    console.warn("[bb] postMessage failed", e);
  }
}
