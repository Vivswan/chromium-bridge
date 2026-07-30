// One owner for the transient-CDP-attach protocol every debugger-backed op
// used to repeat by hand (console.ts, dialog.ts, upload.ts, precise.ts):
// reuse the registry's persistent attach when CDP mode already holds the
// tab, attach transiently otherwise, and detach on every exit path exactly
// when this call created the attach. Keeping the sample-then-conditionally-
// detach pair in one place is the point - a caller that forgot the
// `!reusing` guard would detach the persistent session and break CDP mode
// for that tab on every later op.

import { cdpRegistry } from "./registry";
import { dbgAttach, dbgDetach } from "./session";

/** What the callback may know about the attach it is riding: whether it is
 * the registry's persistent one (CDP mode) or a transient one this call
 * owns. Ops that enable CDP domains use it to skip the disable round-trips
 * when the whole transient session is about to be detached anyway. */
export interface CdpAttachHandle {
  reused: boolean;
}

export async function withCdpAttach<T>(
  tabId: number,
  tool: string,
  fn: (handle: CdpAttachHandle) => Promise<T>,
): Promise<T> {
  const reused = cdpRegistry.hasSession(tabId);
  try {
    if (reused) {
      // Await the registry's idempotent (de-duped) attach so we never issue
      // CDP commands before a still-in-flight persistent attach completes.
      await cdpRegistry.get(tabId);
    } else {
      await dbgAttach(tabId);
    }
  } catch (e) {
    // Map the attach-conflict failure per tool on BOTH paths: the transient
    // attach reports it raw ("another debugger"), the registry's shared
    // attach reports it already session-mapped ("DevTools is open").
    const msg = String((e as Error).message || e);
    if (/another debugger|DevTools is open/i.test(msg)) {
      throw new Error(
        `${tool} cannot attach: DevTools is open on this tab. Close DevTools and retry.`,
        { cause: e },
      );
    }
    throw e;
  }
  try {
    return await fn({ reused });
  } finally {
    // Detach exactly when this call attached: a transient attach never
    // outlives its op, and the persistent session is never torn down here.
    if (!reused) await dbgDetach(tabId);
  }
}
