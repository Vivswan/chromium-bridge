// Native-messaging port lifecycle. MV3 service workers are killed ~every 5 min
// and Chrome kills the host process whenever the port closes, so we reconnect
// automatically on startup and after any disconnect.

import { maskErrorMessage } from "../shared/masking";
import type { BridgeReq } from "../shared/types";
import { dispatch } from "./dispatch";
import {
  attachPort,
  detachPort,
  enrollmentGate,
  handleEnclaveFrame,
  isEnclaveFrame,
  onPortConnected,
} from "./enrollment";

const NATIVE_HOST = "com.vivswan.chromium_bridge.host";

let port: chrome.runtime.Port | null = null;
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
    port = chrome.runtime.connectNative(NATIVE_HOST);
    portOk = true;
    console.log("[bb] native host connected");
    port.onMessage.addListener(onNativeMessage);
    port.onDisconnect.addListener(onNativeDisconnect);
    // Hand the enrollment ceremony (ADR-0021) the fresh port. It decides
    // whether this connect needs a pairing challenge.
    attachPort(postFrame);
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

function onNativeDisconnect(_p: chrome.runtime.Port) {
  portOk = false;
  port = null;
  detachPort();
  const err = chrome.runtime.lastError;
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

function onNativeMessage(msg: BridgeReq) {
  // Enclave control frames (ADR-0021) are ceremony traffic between the
  // extension and the host itself; they carry `type`, not `op`, and are never
  // dispatched as bridge ops.
  if (isEnclaveFrame(msg)) {
    void handleEnclaveFrame(msg);
    return;
  }
  // Each message is a BridgeReq: { id, op, tabId?, args }. Guard defensively —
  // it crosses the native-messaging boundary.
  if (!msg || typeof msg.id === "undefined" || !msg.op) {
    console.warn("[bb] malformed BridgeReq", msg);
    return;
  }
  // Fail closed (ADR-0021): while enrollment is required and unsatisfied,
  // every bridge request is refused right here and never reaches dispatch().
  // The dispatch kickoff is passed INTO the gate so it starts inside the
  // gate's serialized critical section: a revoke or compromise mark can then
  // never land between "gate said allowed" and "dispatch began".
  enrollmentGate(() => {
    dispatch(msg).then(
      (data) => sendResponse(msg.id, true, data),
      // A rejection message can embed page-derived data (a CDP evaluate
      // exception carries the page's error description), so this egress is
      // masked like any other.
      (err) => sendResponse(msg.id, false, undefined, maskErrorMessage(err)),
    );
  }).then(
    (gate) => {
      if (!gate.allowed) sendResponse(msg.id, false, undefined, gate.reason);
    },
    // Gate errors are ambiguity, and ambiguity refuses.
    (err) => sendResponse(msg.id, false, undefined, `enrollment gate error: ${String(err)}`),
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
