import { browser } from "wxt/browser";
import { defineBackground } from "wxt/utils/define-background";
import { syncPendingMirror } from "@/lib/background/allowlist-store";
import { installCdpLifecycleListeners } from "@/lib/background/cdp/registry";
import { EnclavePresenceProvider } from "@/lib/background/confirm/presence";
import {
  installConfirmationProvider,
  installPresenceProvider,
} from "@/lib/background/confirm/service";
import { ExtensionWindowProvider } from "@/lib/background/confirm/surface";
import { verifyExtensionId } from "@/lib/background/id-check";
import { installLegacyCleanup } from "@/lib/background/legacy-cleanup";
import { registerRuntimeMessageRouter } from "@/lib/background/messages";
import { registerUnpinnedRelaxationApprover } from "@/lib/background/policy-approval";
import { connectNative } from "@/lib/background/port";
import { hardenStorageAccess } from "@/lib/background/trusted-storage";
import { migrateSettings } from "@/lib/shared/settings-migration";

// MV3 service worker entry point. Thin wiring only; the real logic lives in
// lib/background/*:
//   - port.ts             native-messaging port lifecycle + reconnect
//   - dispatch.ts         route a BridgeReq to the right handler
//   - tabs.ts             tab resolution/injection + tab_* tools
//   - precise.ts          page_snapshot_precise (browser.debugger / CDP)
//   - cookies.ts          cookie_get (browser.cookies, SW-only)
//   - allowlist-store.ts  storage-backed allowlist + approval flow
//   - messages.ts         runtime message router (popup/options/screenshot)
export default defineBackground(() => {
  // #32: confine browser.storage to extension contexts as early as possible,
  // so a content script cannot read or write the enrollment pin, the
  // compromised marker, the policy state, or the allowlist. This eager call
  // only STARTS the async restriction; the enrollment gate and
  // onPortConnected AWAIT its success and fail closed until it lands, so no
  // trust decision is ever made on un-confined storage. See the residual note
  // in trusted-storage.ts for the unavoidable sub-ms cold-start window.
  void hardenStorageAccess();

  // Run any pending settings migrations (versioned storage). Best-effort:
  // failure never blocks startup - the per-field salvage in shared/settings
  // keeps reads safe regardless.
  void migrateSettings().catch((e) => console.warn("[bb] settings migration failed", e));

  // Loudly log if the running extension id is not the pinned id. A mismatch
  // means the native host rejects this extension (allowed_origins pins the
  // id) - the most common "won't connect" cause.
  verifyExtensionId();

  // Runtime message router for the popup/options pages and the content
  // script's screenshot proxy. Registered inside defineBackground (not at
  // module load) so importing lib modules stays side-effect-free.
  registerRuntimeMessageRouter();

  // CDP mode (ADR-0017): tear down debugger sessions when a tab closes, when
  // Chrome detaches us, or when the effective cdpMode grant goes away.
  installCdpLifecycleListeners();

  // ADR-0032 Phase 5: ONE startup sweep that deletes the retired legacy
  // policy keys (+ requireEnrollment) from storage, only when the one-way
  // cutover has armed AND the legacy bag shipped (legacySettingsSent) - no
  // storage watch, by design (legacy-cleanup.ts: startup-only closes the
  // read/delete race by construction). Pre-cutover (non-macOS forever, old
  // hosts indefinitely) and armed-but-never-shipped both delete nothing.
  installLegacyCleanup();

  // The off-DOM confirmation surface (ADR-0027). Without a provider the
  // confirmation service denies everything, so install it before any bridge
  // traffic can arrive. The Enclave user-presence provider (ADR-0031) rides
  // on top of it for the "eval"/"upload" kinds: whether a given confirmation
  // routes to it is decided by the caller at decision time (ConfirmRequest's
  // presenceRouting, from the per-request policy snapshot); the window
  // displays what is being approved, the Touch ID tap (a verified host
  // signature) approves.
  const windowProvider = new ExtensionWindowProvider();
  installConfirmationProvider(windowProvider);
  installPresenceProvider(new EnclavePresenceProvider(windowProvider));

  // Lane U (ADR-0032 decision 3): on an UNPINNED extension, an unsigned
  // policy push that would relax the enforced effective policy is applied
  // only after an explicit approval in the confirmation window above.
  // Registered after the provider so a consultation always has a surface;
  // policy-sync refuses every relaxation while this seam is empty, and never
  // consults it on a pinned extension.
  registerUnpinnedRelaxationApprover();

  // Every connect path first COMPLETES the pending-approval sweep, then
  // connects. The sweep re-derives the popup mirror and badge from this
  // worker's (empty) resolver map, clearing any ghost record a previous
  // worker life left behind. Sequencing it strictly before connectNative is
  // what makes the badge deterministic: enrollment writes its own badge
  // after the port connects, so a sweep whose badge clear landed LATE would
  // wipe a just-written PAIR/! marker. The listeners themselves are
  // registered synchronously (an MV3 requirement); only the work inside is
  // sequenced. A sweep REJECTION never blocks connecting (caught below) -
  // the bridge matters more than a stale badge.
  const startUp = () => {
    void (async () => {
      await syncPendingMirror().catch((e) => {
        console.warn("[bb] pending-approval sweep failed", e);
      });
      // Connect eagerly whenever the SW wakes. connectNative consumes any
      // previous link first, so repeated calls are safe.
      connectNative();
    })();
  };
  browser.runtime.onStartup.addListener(startUp);
  browser.runtime.onInstalled.addListener(startUp);
  startUp();
});
