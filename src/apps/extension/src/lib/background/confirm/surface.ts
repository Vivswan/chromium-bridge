// The default ConfirmationProvider: a dedicated extension-owned popup window
// (confirm.html). Being a chrome-extension:// page in its own window, it is
// out of reach of any guarded page: no page script can read, focus, overlay,
// or click it, and the message router refuses confirm_* messages from
// non-extension senders. Approvals arrive through confirm_resolve (router ->
// service.resolveConfirm); this provider itself only reports denials: the
// window was closed without answering, or it failed to open at all.

import type { ConfirmPayload } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import type { ConfirmationProvider, Presentation } from "./service";

const WINDOW_WIDTH = 460;
const WINDOW_HEIGHT = 600;

export class ExtensionWindowProvider implements ConfirmationProvider {
  // windowId -> deny, so onRemoved can settle a closed-without-answer window.
  private open = new Map<number, () => void>();
  private listenerInstalled = false;

  private installOnRemoved(): void {
    if (this.listenerInstalled) return;
    this.listenerInstalled = true;
    browser.windows.onRemoved.addListener((windowId) => {
      const deny = this.open.get(windowId);
      if (deny) {
        this.open.delete(windowId);
        deny(); // closed without answering = denied
      }
    });
  }

  present(payload: ConfirmPayload): Presentation {
    this.installOnRemoved();
    let windowId: number | undefined;
    let dismissed = false;
    let deny!: () => void;
    const verdict = new Promise<boolean>((resolve) => {
      deny = () => resolve(false);
    });

    browser.windows
      .create({
        url: browser.runtime.getURL(`/confirm.html?id=${encodeURIComponent(payload.id)}`),
        type: "popup",
        focused: true,
        width: WINDOW_WIDTH,
        height: WINDOW_HEIGHT,
      })
      .then(
        (win) => {
          if (win?.id === undefined) {
            deny(); // no window = no consent
            return;
          }
          if (dismissed) {
            // The service settled (deadline) while the window was opening.
            browser.windows.remove(win.id).catch(() => {});
            return;
          }
          windowId = win.id;
          this.open.set(win.id, deny);
        },
        (e: unknown) => {
          console.error("[bb] confirmation window failed to open; denying", e);
          deny();
        },
      );

    return {
      verdict,
      dismiss: () => {
        dismissed = true;
        if (windowId !== undefined) {
          this.open.delete(windowId);
          // Best-effort close; the user may have closed it already.
          browser.windows.remove(windowId).catch(() => {});
          windowId = undefined;
        }
      },
    };
  }
}
