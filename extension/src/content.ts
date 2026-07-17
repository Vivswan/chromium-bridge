// content.ts — injected into each page by background.ts. Receives { op, args }
// from the service worker via chrome.runtime.onMessage and runs the DOM
// operation, replying with JSON-serializable data or { __error }.
//
// This entry stays intentionally tiny: the re-injection guard and the message
// listener MUST live here (module top-level code in ./content/* runs at bundle
// eval time, before the guard). All real logic lives in ./content/*:
//   refs / snapshot / actions / wait / eval / storage / toast / handle

import { handle } from "./content/handle";
import { maskErrorMessage } from "./shared/masking";

declare global {
  interface Window {
    __chromiumBridgeLoaded?: boolean;
  }
}

(() => {
  if (window.__chromiumBridgeLoaded) return; // guard against double-inject
  window.__chromiumBridgeLoaded = true;

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    handle(msg)
      .then((data) => sendResponse(data || {}))
      // An error message can carry page-derived data (a getter that throws, a
      // failed op echoing page state), so this egress is masked like any other.
      .catch((e) => sendResponse({ __error: maskErrorMessage(e) }));
    return true; // keep the channel open for the async response
  });
})();

export {};
