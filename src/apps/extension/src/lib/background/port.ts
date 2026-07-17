// Native-messaging port lifecycle. MV3 service workers are killed ~every 5 min
// and Chrome kills the host process whenever the port closes, so we reconnect
// automatically on startup and after any disconnect.

import { NATIVE_HOST_ID, parseBridgeReq } from "@chromium-bridge/shared";
import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { maskErrorMessage } from "../shared/masking";
import * as auditLog from "./audit-log";
import * as clients from "./clients";
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

let port: Browser.runtime.Port | null = null;
let portOk = false; // did the most recent connect succeed?
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

export function isNativeConnected(): boolean {
  return portOk;
}

export function connectNative() {
  // Tear down any previous handle first.
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  try {
    port = browser.runtime.connectNative(NATIVE_HOST_ID);
    portOk = true;
    console.log("[bb] native host connected");
    port.onMessage.addListener(onNativeMessage);
    port.onDisconnect.addListener(onNativeDisconnect);
    // Hand the enrollment ceremony (ADR-0021), the trusted-client admin
    // exchange (ADR-0025), and the kill-switch/audit surfaces (ADR-0030) the
    // fresh port. Enrollment decides whether this connect needs a pairing
    // challenge or a pending host-key deletion.
    attachPort(postFrame);
    clients.attachPort(postFrame);
    kill.attachPort(postFrame);
    auditLog.attachPort(postFrame);
    // Pull the kill state on every connect (ADR-0030): this is what clears a
    // stale "killed" mirror after a CLI unkill that happened while the SW
    // slept (the host pushes transitions and bad startup states, but the
    // alive direction is deliberately pull-based). The result routes through
    // handleKillFrame like any other kill_status_result.
    void kill.requestKillStatus();
    void onPortConnected();
  } catch (e) {
    portOk = false;
    console.error("[bb] connectNative threw", e);
    scheduleReconnect();
  }
}

// Raw frame sender for enclave control frames (they are not BridgeResps).
function postFrame(frame: object): boolean {
  if (!port) return false;
  try {
    port.postMessage(frame);
    return true;
  } catch (e) {
    console.warn("[bb] postFrame failed", e);
    return false;
  }
}

function onNativeDisconnect(_p: Browser.runtime.Port) {
  portOk = false;
  port = null;
  detachPort();
  clients.detachPort();
  kill.detachPort();
  auditLog.detachPort();
  const err = browser.runtime.lastError;
  console.warn("[bb] native host disconnected:", err?.message || "unknown");
  // Chrome kills the host process when the Port drops. Reconnect so a fresh
  // host is spawned — but back off to avoid a tight loop if the host is
  // genuinely unavailable (e.g. install not finished).
  scheduleReconnect();
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectNative();
  }, 2000);
}

function onNativeMessage(msg: unknown) {
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
  if (!port) return; // host gone; nothing to do
  try {
    port.postMessage({ id, ok, data, error: ok ? undefined : error });
  } catch (e) {
    // Port likely closed; the disconnect handler will reconnect.
    console.warn("[bb] postMessage failed", e);
  }
}
