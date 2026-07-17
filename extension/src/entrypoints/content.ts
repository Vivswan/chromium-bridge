import { browser } from "wxt/browser";
import { defineContentScript } from "wxt/utils/define-content-script";
import { handle } from "@/lib/content/handle";
import { maskErrorMessage } from "@/lib/shared/masking";

declare global {
  interface Window {
    __chromiumBridgeLoaded?: boolean;
  }
}

// Injected into a page by the service worker (registration: "runtime" keeps
// it out of the manifest; lib/background/tabs.ts injects it on demand once
// the user has approved the origin). Receives { op, args } from the service
// worker via runtime.onMessage and runs the DOM operation, replying with
// JSON-serializable data or { __error }.
export default defineContentScript({
  // Injected at RUNTIME only (lib/background/tabs.ts, after the user approves
  // the origin), never declared in the manifest. matches stays EMPTY so WXT
  // does not promote it into host_permissions: origin access is the optional
  // <all_urls> permission, granted per-origin through the allowlist flow -
  // install-time host access would defeat that model.
  matches: [],
  registration: "runtime",
  main() {
    if (window.__chromiumBridgeLoaded) return; // guard against double-inject
    window.__chromiumBridgeLoaded = true;

    browser.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      handle(msg)
        .then((data) => sendResponse(data || {}))
        // An error message can carry page-derived data (a getter that throws,
        // a failed op echoing page state), so this egress is masked like any
        // other.
        .catch((e: unknown) => sendResponse({ __error: maskErrorMessage(e) }));
      return true; // keep the channel open for the async response
    });
  },
});
