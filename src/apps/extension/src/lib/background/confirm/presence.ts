// The presence route for page_eval and page_upload: the provider the service hands a presence-gated confirmation
// to. It asks the host for a presence request bound to the op and the page's origin, then shows the same
// extension-owned window, where the user answers that request (a tap on this browser's enrolled authenticator,
// or the software confirmation where none is enrolled). The host verifies and audits the answer; its verdict is
// this presentation's verdict. The window's own Allow is refused by the service for this payload.
//
//   presence_begin refused (host gone, exchange busy, an origin the host would not mint a statement for)
//                                        -> denied, no window opens: a probe that fails never downgrades to a
//                                           window click (the policy ledger's rule)
//   presence_request                     -> the window opens; the host's presence_result on the window's answer
//                                           settles the verdict and the service closes the window
//   window closed unanswered, deadline   -> denied; the held request is forgotten, and a begin the host has not
//                                           answered yet is withdrawn so the exchange is free for the next act

import { abandonPresence, beginPresence, type PresenceAction } from "../../webauthn/exchange";
import type {
  ConfirmationProvider,
  PresencePayload,
  PresenceProvider,
  Presentation,
} from "./service";

const ACTION: Record<PresencePayload["kind"], PresenceAction> = {
  eval: "page_eval",
  upload: "page_upload",
};

/** Where one presentation stands: the host asked, the window up over the host's request (whose nonce exists
 * only once the host answered), or over (dismissed by the service). */
type Phase =
  | { at: "asking" }
  | { at: "shown"; nonce: string; window: Presentation }
  | { at: "over" };

export class PresenceExchangeProvider implements PresenceProvider {
  constructor(private readonly surface: ConfirmationProvider) {}

  present(payload: PresencePayload): Presentation {
    let phase: Phase = { at: "asking" };
    let settle!: (ok: boolean) => void;
    const hostVerdict = new Promise<boolean>((resolve) => {
      settle = resolve;
    });
    let surfaceUp!: (up: boolean) => void;
    const shown = new Promise<boolean>((resolve) => {
      surfaceUp = resolve;
    });
    const begin = beginPresence(ACTION[payload.kind], payload.origin, settle);
    const verdict = begin.view.then((view) => {
      if (!view.ok) {
        console.warn(`[bb] the host refused a presence request for ${payload.kind}: ${view.error}`);
        surfaceUp(false);
        return false;
      }
      if (phase.at === "over") {
        abandonPresence(view.request.nonce);
        surfaceUp(false);
        return false;
      }
      const window = this.surface.present(payload);
      phase = { at: "shown", nonce: view.request.nonce, window };
      // Shown is the surface's own word where it has one; a surface that only reports verdicts counts as up.
      void (window.shown ?? Promise.resolve(true)).then(surfaceUp);
      // The window reports only denials of its own (closed without answering); the approval is the host's.
      return Promise.race([hostVerdict, window.verdict.then(() => false)]);
    });
    return {
      verdict,
      shown,
      dismiss() {
        if (phase.at === "asking") begin.cancel();
        if (phase.at === "shown") {
          phase.window.dismiss();
          abandonPresence(phase.nonce);
        }
        phase = { at: "over" };
        surfaceUp(false);
      },
    };
  }
}
