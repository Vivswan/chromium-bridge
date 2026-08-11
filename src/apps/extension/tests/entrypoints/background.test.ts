// Entrypoint wiring: the background service worker MUST invoke the #32 storage
// hardening at startup (and the other one-time setup). This closes the gap the
// isolated-browser proof cannot observe (Chrome has no getAccessLevel), by
// asserting the production call site exists and runs. If someone deletes the
// hardenStorageAccess() call from the entrypoint, this fails.

import { beforeEach, describe, expect, test, vi } from "vitest";

// Mock every collaborator the entrypoint calls so main() runs in isolation and
// we can observe which startup steps fire.
const harden = vi.fn(() => Promise.resolve({ ok: true as const }));
const migrate = vi.fn(() => Promise.resolve());
const verifyId = vi.fn();
const registerRouter = vi.fn();
const installCdp = vi.fn();
const installLegacyCleanup = vi.fn();
const installConfirm = vi.fn();
const installPresence = vi.fn();
// The startup order is load-bearing: the pending-approval sweep must COMPLETE
// before the eager connect, or its badge clear could land after enrollment's
// PAIR/! write (triggered by the connect) and hide it. Record completion vs
// invocation explicitly.
const order: string[] = [];
const connect = vi.fn(() => {
  order.push("connect");
});
const sweepPending = vi.fn(async () => {
  await new Promise((r) => setTimeout(r, 0)); // a real async hop, like storage I/O
  order.push("sweep-complete");
});

vi.mock("@/lib/background/trusted-storage", () => ({ hardenStorageAccess: harden }));
vi.mock("@/lib/shared/settings-migration", () => ({ migrateSettings: migrate }));
vi.mock("@/lib/background/id-check", () => ({ verifyExtensionId: verifyId }));
vi.mock("@/lib/background/messages", () => ({ registerRuntimeMessageRouter: registerRouter }));
vi.mock("@/lib/background/cdp/registry", () => ({ installCdpLifecycleListeners: installCdp }));
vi.mock("@/lib/background/legacy-cleanup", () => ({ installLegacyCleanup }));
vi.mock("@/lib/background/allowlist-store", () => ({ syncPendingMirror: sweepPending }));
vi.mock("@/lib/background/confirm/service", () => ({
  installConfirmationProvider: installConfirm,
  installPresenceProvider: installPresence,
}));
vi.mock("@/lib/background/confirm/surface", () => ({ ExtensionWindowProvider: class {} }));
vi.mock("@/lib/background/confirm/presence", () => ({
  EnclavePresenceProvider: class {},
  presenceRoutingEnabled: vi.fn(() => Promise.resolve(false)),
}));
vi.mock("@/lib/background/port", () => ({ connectNative: connect }));

// defineBackground returns its callback as `.main`; capture it.
vi.mock("wxt/utils/define-background", () => ({
  defineBackground: (cb: () => void) => ({ main: cb }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  order.length = 0;
});

describe("background entrypoint", () => {
  test("startup invokes #32 storage hardening (and the other one-time setup)", async () => {
    const mod = await import("@/entrypoints/background");
    const def = mod.default as unknown as { main: () => void };
    def.main();
    // The #32 isolation must be applied at startup - this is the production
    // call the isolated-browser proof cannot observe.
    expect(harden).toHaveBeenCalledTimes(1);
    // The rest of the one-time wiring must also fire.
    expect(migrate).toHaveBeenCalledTimes(1);
    expect(registerRouter).toHaveBeenCalledTimes(1);
    expect(installCdp).toHaveBeenCalledTimes(1);
    // The Phase 5 legacy cleanup must be wired at startup: post-cutover the
    // retired keys are swept, pre-cutover it deletes nothing.
    expect(installLegacyCleanup).toHaveBeenCalledTimes(1);
    // The startup pending-approval sweep clears a ghost record a prior worker
    // life left behind (stuck badge / a popup Allow for an origin the SW
    // would then refuse).
    expect(sweepPending).toHaveBeenCalledTimes(1);
    expect(installConfirm).toHaveBeenCalledTimes(1);
    // The Enclave user-presence provider (ADR-0031) must be wired at startup
    // too, or eval/upload confirmations silently stay window-only.
    expect(installPresence).toHaveBeenCalledTimes(1);
    expect(verifyId).toHaveBeenCalledTimes(1);
    // The connect happens only after the sweep COMPLETED (not merely began):
    // a sweep badge-clear landing after the connect-triggered enrollment
    // badge write would hide it.
    await vi.waitFor(() => expect(connect).toHaveBeenCalled());
    expect(order).toEqual(["sweep-complete", "connect"]);
  });
});
