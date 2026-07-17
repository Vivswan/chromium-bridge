import { browser } from "wxt/browser";
import { defineBackground } from "wxt/utils/define-background";
import { installCdpLifecycleListeners } from "@/lib/background/cdp/registry";
import { installConfirmationProvider } from "@/lib/background/confirm/service";
import { ExtensionWindowProvider } from "@/lib/background/confirm/surface";
import { verifyExtensionId } from "@/lib/background/id-check";
import { registerRuntimeMessageRouter } from "@/lib/background/messages";
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
  // compromised marker, requireEnrollment, or the allowlist. This eager call
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
  // Chrome detaches us, or when the user turns cdpMode off.
  installCdpLifecycleListeners();

  // The off-DOM confirmation surface (ADR-0027). Without a provider the
  // confirmation service denies everything, so install it before any bridge
  // traffic can arrive.
  installConfirmationProvider(new ExtensionWindowProvider());

  browser.runtime.onStartup.addListener(connectNative);
  browser.runtime.onInstalled.addListener(connectNative);
  // Also connect eagerly when the SW wakes for any reason. connectNative is
  // idempotent-ish: if a port already exists it creates a new one and the old
  // is replaced.
  connectNative();
});
