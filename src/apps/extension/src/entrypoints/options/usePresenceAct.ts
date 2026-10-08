import type { PresenceRequestFrame } from "@genkan/shared/generated/envelope";
import type { Refusal } from "@genkan/shared/runtime-msg";
import { useCallback, useState } from "react";
import { flushSync } from "react-dom";
import { send } from "@/lib/messages";
import { ceremonyFailure } from "@/lib/refusals";
import { assert } from "@/lib/shared/webauthn-ceremony";

// One presence-gated act as the options page runs it, whichever panel asked (the kill release, a policy grant or
// relaxing rollback, a client pairing): the panel posts the message that begins it, the host answers with its
// presence request, this browser's authenticator signs it, and the answer's verdict is the act's outcome. The
// panel never claims an outcome itself; the host decides and audits.
//
//   begin -> { request: null }   the host applied the act on its free lane; nothing to answer
//   begin -> { request }         allowed_credential_ids empty -> the window may confirm (the host re-checks that
//                                when the answer arrives); otherwise this browser's authenticator signs it
//   begin -> { ok: false }       the host's refusal before any request, in the CLI's words
//
// Every state that holds the host's request carries it, so the page can show what the tap or the click
// approves before the authenticator is asked; WebAuthn's request options have no field for that text (the
// challenge is the host's statement, which binds it).

export type PresenceAct =
  | { kind: "idle" }
  | { kind: "asking" }
  | { kind: "tapping"; request: PresenceRequestFrame }
  | { kind: "confirm_window"; request: PresenceRequestFrame }
  | { kind: "confirming" }
  | { kind: "refused"; reason: string };

/** How an act began, as the runtime contract answers kill_release, grant_policy, rollback_policy, and
 * pair_client. */
export type ActBegun = { ok: true; request: PresenceRequestFrame | null } | Refusal;

/** The states in which the host holds an act the page has not settled: the controls that could start another
 * act, or edit what this one was asked for, are disabled in all of them (`confirm_window` included, since the
 * offered click answers for the values first submitted). */
const PENDING: ReadonlySet<PresenceAct["kind"]> = new Set([
  "asking",
  "tapping",
  "confirm_window",
  "confirming",
]);

export interface PresenceActControls {
  act: PresenceAct;
  /** An act is outstanding on this hook. */
  busy: boolean;
  /** Run one act from the message that begins it. */
  run: (begin: () => Promise<ActBegun>) => Promise<void>;
  /** The window's answer to a request that admits no credential. */
  confirmWindow: (request: PresenceRequestFrame) => Promise<void>;
  cancel: () => void;
}

/** `onApplied` runs once the host reports the act done, for a panel whose view the host does not push to it. */
export function usePresenceAct(onApplied?: () => void): PresenceActControls {
  const [act, setAct] = useState<PresenceAct>({ kind: "idle" });

  const settle = useCallback(
    (verdict: { ok: true } | Refusal) => {
      if (verdict.ok) {
        setAct({ kind: "idle" });
        onApplied?.();
      } else {
        setAct({ kind: "refused", reason: verdict.error });
      }
    },
    [onApplied],
  );

  const tap = useCallback(
    async (request: PresenceRequestFrame) => {
      // Committed before the authenticator's prompt covers the page, not merely scheduled.
      flushSync(() => setAct({ kind: "tapping", request }));
      let response: Awaited<ReturnType<typeof assert>>;
      try {
        response = await assert(request);
      } catch (e) {
        setAct({ kind: "refused", reason: ceremonyFailure(e) });
        return;
      }
      settle(await send({ type: "webauthn_presence_assert", nonce: request.nonce, ...response }));
    },
    [settle],
  );

  const run = useCallback(
    async (begin: () => Promise<ActBegun>) => {
      setAct({ kind: "asking" });
      const begun = await begin();
      if (!begun.ok) {
        setAct({ kind: "refused", reason: begun.error });
        return;
      }
      if (begun.request === null) {
        settle({ ok: true });
        return;
      }
      if (begun.request.allowed_credential_ids.length === 0) {
        setAct({ kind: "confirm_window", request: begun.request });
        return;
      }
      await tap(begun.request);
    },
    [settle, tap],
  );

  const confirmWindow = useCallback(
    async (request: PresenceRequestFrame) => {
      setAct({ kind: "confirming" });
      settle(await send({ type: "webauthn_presence_confirm", nonce: request.nonce }));
    },
    [settle],
  );

  const cancel = useCallback(() => setAct({ kind: "idle" }), []);

  return { act, busy: PENDING.has(act.kind), run, confirmWindow, cancel };
}
