// The webview side of the app's epoch watch (D-P4-1): subscribe to the
// change notices the Rust watch thread emits when the host's revocation
// epochs move. The events carry no authority - listeners re-READ the state
// through the pull-based commands; the payload (the new epoch) is not even
// surfaced here.

import { listen } from "@tauri-apps/api/event";

/** A policy write landed somewhere (this app, the CLI, a rollback):
 * re-read policyStatus / pendingImport. */
export const POLICY_EPOCH_EVENT = "policy-epoch-changed";

/** The shared language changed (the extension's picker, or our own set -
 * harmless, the re-read is a no-op): re-read langCurrent. */
export const LANG_EPOCH_EVENT = "lang-epoch-changed";

export type EpochEventName = typeof POLICY_EPOCH_EVENT | typeof LANG_EPOCH_EVENT;

/** Subscribe to one epoch change notice. Returns a synchronous disposer
 * (Tauri's own unlisten resolves asynchronously; the disposer handles the
 * subscribe-then-unmount race). Outside a Tauri window (tests, plain-browser
 * dev) the subscription fails silently: live notices are a convenience, and
 * every surface still pulls. */
export function onEpochEvent(event: EpochEventName, handler: () => void): () => void {
  let disposed = false;
  let unlisten: (() => void) | undefined;
  listen(event, () => handler()).then(
    (fn) => {
      if (disposed) fn();
      else unlisten = fn;
    },
    () => {
      // No Tauri event bridge here: stay pull-only.
    },
  );
  return () => {
    disposed = true;
    unlisten?.();
  };
}
