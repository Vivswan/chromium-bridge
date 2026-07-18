// The user-confirmation service (ADR-0027): every confirmation the bridge
// asks for goes through confirmWithUser(), which presents the request on an
// EXTENSION-OWNED surface the guarded page cannot reach, script, or
// auto-click. This replaces the in-page toasts of ADR-0006/0008: a page
// script could observe and click a toast rendered in its own DOM, so consent
// could be forged exactly where it mattered most. The extension window is a
// separate chrome-extension:// document in a separate process; the router
// additionally refuses confirm_* messages from anything but extension pages.
//
// Fail-closed properties:
// - unanswered within the timeout -> denied (and the surface is dismissed);
// - surface closed by the user -> denied;
// - the surface failing to open -> denied;
// - a second resolution for the same id -> ignored (single-use);
// - no provider installed -> denied;
// - SW death loses the in-flight request -> the op fails; nothing dangles.
//
// Requests are serialized: one confirmation surface at a time, FIFO. A queued
// request's timeout clock starts when it is SHOWN, not when queued.
//
// Phase 8 (ADR-0031): providers implement ConfirmationProvider. The default
// is the extension popup window (surface.ts). The "eval" and "upload" kinds
// route to the Enclave user-presence provider (presence.ts) when the user
// setting is on and the device is capable (macOS + pinned host key) - the
// host raises the Touch ID prompt and the provider resolves its verdict from
// the host's SIGNED answer, with a display-only window showing WHAT is being
// approved. Such payloads carry `hardware: true`, and resolveConfirm refuses
// a window-side approval for them: the tap is the only approval. The queue,
// deadline, and fail-closed semantics here stay unchanged.

import type { ConfirmKind, ConfirmPayload } from "@chromium-bridge/shared";
import { auditEvent } from "../audit-log";

export interface ConfirmRequest {
  kind: ConfirmKind;
  origin: string;
  tabTitle: string;
  detail: string;
  timeoutMs: number;
}

/** A live presentation of one confirmation. */
export interface Presentation {
  /** The provider-observed outcome. The window provider only ever reports
   * denials here (surface closed / failed to open) - approvals arrive
   * through resolveConfirm(), from the extension page, via the router. The
   * Enclave provider (ADR-0031) resolves true here from the host's signed
   * user-presence answer instead. */
  verdict: Promise<boolean>;
  /** Tear the surface down (deadline hit, or resolved through the router). */
  dismiss(): void;
}

export interface ConfirmationProvider {
  present(payload: ConfirmPayload): Presentation;
}

interface Active {
  payload: ConfirmPayload;
  settle: (approved: boolean) => void;
}

// One live confirmation at a time; the rest wait here (FIFO). `running` is
// the SYNCHRONOUS occupancy flag: provider selection awaits (settings,
// capability), so `active` alone would let two same-tick requests both start
// before either registered.
const queue: Array<() => void> = [];
let active: Active | null = null;
let running = false;
let counter = 0;

// Installed by the background entrypoint at SW startup. No provider
// installed = every confirmation denies (fail closed).
let defaultProvider: ConfirmationProvider | null = null;

export function installConfirmationProvider(p: ConfirmationProvider): void {
  defaultProvider = p;
}

// The Enclave user-presence provider (ADR-0031) and its routing predicate,
// both installed at SW startup. `enabled` is consulted per confirmation so a
// settings change applies immediately; a predicate failure routes to the
// window (still a real confirmation), never to "no confirmation".
let presenceProvider: ConfirmationProvider | null = null;
let presenceEnabled: (() => Promise<boolean>) | null = null;

export function installPresenceProvider(
  p: ConfirmationProvider,
  enabled: () => Promise<boolean>,
): void {
  presenceProvider = p;
  presenceEnabled = enabled;
}

/** The provider for a given kind. "eval" and "upload" go to the Enclave
 * user-presence gate when it is installed, enabled, and capable; everything
 * else (and every fallback) keeps the window. `hardware` marks the payload
 * so the window renders display-only and resolveConfirm refuses a window
 * approval. */
async function providerFor(
  kind: ConfirmKind,
): Promise<{ provider: ConfirmationProvider | null; hardware: boolean }> {
  if ((kind === "eval" || kind === "upload") && presenceProvider && presenceEnabled) {
    const routed = await presenceEnabled().catch((e: unknown) => {
      console.warn("[bb] presence routing probe failed; using the window", e);
      return false;
    });
    if (routed) return { provider: presenceProvider, hardware: true };
  }
  return { provider: defaultProvider, hardware: false };
}

/** Ask the user. Resolves true only on an explicit, in-time approval from
 * the extension-owned surface; every other outcome is false. */
export function confirmWithUser(req: ConfirmRequest): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    // Hand the surface to the next queued request, or go idle.
    const advance = () => {
      const next = queue.shift();
      if (next) next();
      else running = false;
    };
    const run = () => {
      running = true;
      void (async () => {
        counter += 1;
        const { provider, hardware } = await providerFor(req.kind);
        const payload: ConfirmPayload = {
          id: `confirm_${Date.now()}_${counter}`,
          kind: req.kind,
          origin: req.origin,
          tabTitle: req.tabTitle,
          detail: req.detail,
          deadline: Date.now() + req.timeoutMs,
          ...(hardware ? { hardware: true } : {}),
        };
        if (!provider) {
          console.error("[bb] no confirmation provider installed; denying", req.kind);
          resolve(false);
          advance();
          return;
        }

        let presentation: Presentation;
        try {
          presentation = provider.present(payload);
        } catch (e) {
          console.error("[bb] confirmation provider threw; denying", e);
          resolve(false);
          advance();
          return;
        }

        let done = false;
        const settle = (approved: boolean) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          active = null;
          try {
            presentation.dismiss();
          } catch (e) {
            // A provider that cannot tear down must not block the verdict or
            // stall the queue.
            console.warn("[bb] confirmation dismiss failed", e);
          }
          // Log-after-decide (ADR-0030): the verdict is already settled; the
          // audit ring and the host's audit file record it, never gate it.
          auditEvent(approved ? "confirm_allowed" : "confirm_denied", {
            tool: req.kind,
            name: req.origin,
          });
          resolve(approved);
          advance();
        };
        const timer = setTimeout(() => settle(false), req.timeoutMs);
        active = { payload, settle };
        // The surface is up in front of the user from here (ADR-0030 audit).
        auditEvent("confirm_shown", { tool: req.kind, name: req.origin });
        presentation.verdict.then(settle, (e: unknown) => {
          console.error("[bb] confirmation presentation failed; denying", e);
          settle(false);
        });
      })();
    };
    if (running) queue.push(run);
    else run();
  });
}

/** The payload the confirmation window asks for on load. Only the ACTIVE
 * request is ever handed out, and only by id: a stale or foreign window gets
 * nothing. */
export function getPendingConfirm(id: string): ConfirmPayload | null {
  return active && active.payload.id === id ? active.payload : null;
}

/** Resolve the active confirmation. Single-use; unknown ids are refused.
 * The router routes this ONLY from extension pages - that restriction is the
 * mechanism that makes page-side auto-approval impossible.
 *
 * A hardware-gated payload (ADR-0031) refuses a window-side APPROVAL: the
 * only approval is the verified Enclave user-presence answer, so even the
 * trusted window cannot substitute for the tap. Denial stays accepted -
 * removing capability is always friction-free. */
export function resolveConfirm(id: string, approved: boolean): { ok: boolean; error?: string } {
  if (!active || active.payload.id !== id) {
    return { ok: false, error: "no such pending confirmation" };
  }
  if (approved && active.payload.hardware) {
    return {
      ok: false,
      error: "hardware-gated confirmation: approval requires the Touch ID prompt",
    };
  }
  active.settle(approved);
  return { ok: true };
}
