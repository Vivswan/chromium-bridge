// CdpSession - a thin Facade over browser.debugger (CDP) for ONE tab.
//
// The promisified attach/detach/send primitives (and the NON_DEBUGGABLE /
// isDebuggable URL filter) were previously private to background/precise.ts.
// They live here now so both precise.ts and the CDP page backend share one
// implementation (see ADR-0017). `evaluate` runs code in the page's MAIN world
// via Runtime.evaluate - this is what lets CDP mode bypass page CSP.

// The subset of the CDP payloads we read (not the full protocol).
import { browser } from "wxt/browser";

interface RemoteObject {
  type?: string;
  className?: string;
  description?: string;
  value?: unknown;
}
interface ExceptionDetails {
  text?: string;
  exception?: RemoteObject;
}
interface EvaluateResponse {
  result?: RemoteObject;
  exceptionDetails?: ExceptionDetails;
}
interface CaptureScreenshotResponse {
  data?: string;
}

// URLs the debugger cannot attach to. Filter before calling attach.
export const NON_DEBUGGABLE = [
  /^chrome:\/\//i,
  /^chrome-extension:\/\//i,
  /^https:\/\/chrome\.google\.com\/webstore/i,
  /^view-source:/i,
  /^about:/i,
  /^edge:\/\//i,
];

export function isDebuggable(url: string | undefined): boolean {
  if (!url) return false;
  return !NON_DEBUGGABLE.some((re) => re.test(url));
}

// Thin browser.debugger primitives (promise API). Exported so precise.ts
// reuses them.
export function dbgAttach(tabId: number): Promise<void> {
  return browser.debugger.attach({ tabId }, "1.3");
}

export async function dbgDetach(tabId: number): Promise<void> {
  // detach must never throw - used in finally / teardown. Swallow errors.
  try {
    await browser.debugger.detach({ tabId });
  } catch {
    // Already detached (tab gone, Chrome pulled the session); nothing to do.
  }
}

export async function dbgSend<T = unknown>(
  tabId: number,
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  return (await browser.debugger.sendCommand({ tabId }, method, params)) as T;
}

// Build a Runtime.evaluate expression that invokes a page function with args.
// The function is stringified and applied to the JSON-serialized args, so it
// runs self-contained in the page - it must NOT close over module scope.
export function buildEvaluateExpression(
  fn: (...args: never[]) => unknown,
  args: readonly unknown[] = [],
): string {
  return `(${fn.toString()}).apply(undefined, ${JSON.stringify(args)})`;
}

// Turn a CDP exceptionDetails into a single-line error message.
export function evalExceptionMessage(details: ExceptionDetails): string {
  const desc = details.exception?.description;
  if (desc) return desc.split("\n")[0] ?? desc;
  return details.text || "evaluation failed";
}

// A session is in exactly one of these states. One value, not an `attached`
// boolean beside a nullable in-flight promise: that pair let a detach during
// an in-flight attach no-op (both fields read "not attached"), leaving an
// ownerless live debugger attach - a stuck banner cdpMode-off teardown could
// never reach.
type SessionState =
  | { phase: "detached" }
  | { phase: "attaching"; attach: Promise<void> }
  | { phase: "attached" };

export class CdpSession {
  readonly tabId: number;
  private state: SessionState = { phase: "detached" };
  /** Whether THIS session may issue the orphan-cleanup detach for its tab.
   * browser.debugger.detach is TAB-scoped, not session-scoped: without this
   * guard, a stale session's won-but-unowned attach settling late would rip
   * down a NEWER session that has since attached to the same tab. The
   * registry wires it to "the tab's current session is still me, or nobody's"
   * (registry.ts). Required, not defaulted: a permissive default would hand
   * any future direct construction the unguarded tab-scoped detach back. */
  private readonly mayCleanupOrphan: () => boolean;

  constructor(tabId: number, mayCleanupOrphan: () => boolean) {
    this.tabId = tabId;
    this.mayCleanupOrphan = mayCleanupOrphan;
  }

  get isAttached(): boolean {
    return this.state.phase === "attached";
  }

  // Attach the debugger to this tab. Idempotent: a no-op if already attached.
  // The banner ("Started debugging this browser") stays up until detach - by
  // design in CDP mode (ADR-0017), the registry keeps sessions attached.
  //
  // Concurrent attaches share the one in-flight promise. Without this, two
  // page ops racing on a fresh tab each issue browser.debugger.attach; the
  // second fails ("another debugger is already attached"), and the caller's
  // cleanup deletes the session the first successfully attached - orphaning
  // the debugger (stuck banner, CDP broken for that tab).
  attach(): Promise<void> {
    const s = this.state;
    if (s.phase === "attached") return Promise.resolve();
    if (s.phase === "attaching") return s.attach;
    const attach = this.doAttach();
    const next: SessionState = { phase: "attaching", attach };
    this.state = next;
    // The transition consumes exactly the attaching state it created. If a
    // markDetached (Chrome pulled the session) or a detach replaced it while
    // the attach was in flight, the settling attach must not resurrect it -
    // and if it WON a real browser.debugger attach that nobody now holds, it
    // gets cleaned up here so no debugger is left orphaned (the banner's
    // stuck-on failure, in the opposite direction from detach-during-attach).
    // The cleanup is identity-guarded (mayCleanupOrphan): dbgDetach is
    // tab-scoped, so a stale session must never fire it while a NEWER
    // session owns the tab.
    attach.then(
      () => {
        if (this.state === next) this.state = { phase: "attached" };
        else if (this.mayCleanupOrphan()) void dbgDetach(this.tabId);
      },
      () => {
        if (this.state === next) this.state = { phase: "detached" };
      },
    );
    return attach;
  }

  private async doAttach(): Promise<void> {
    try {
      await dbgAttach(this.tabId);
    } catch (e) {
      const msg = String((e as Error).message || e);
      if (/another debugger/i.test(msg)) {
        throw new Error(
          "CDP mode cannot attach: DevTools is open on this tab. Close DevTools and retry.",
          {
            cause: e,
          },
        );
      }
      throw e;
    }
  }

  async detach(): Promise<void> {
    const s = this.state;
    if (s.phase === "detached") return;
    if (s.phase === "attaching") {
      // A detach must account for an in-flight attach winning the race:
      // wait for it to settle, then tear down whatever it produced. The
      // settled transition above runs first (registered at attach time), so
      // the re-read below sees the post-attach state.
      await s.attach.catch(() => {});
    }
    if (this.state.phase !== "attached") return;
    this.state = { phase: "detached" };
    await dbgDetach(this.tabId);
  }

  // Mark the session as detached WITHOUT calling browser.debugger.detach - for
  // the case where Chrome already detached us (onDetach event).
  markDetached(): void {
    this.state = { phase: "detached" };
  }

  send<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    return dbgSend<T>(this.tabId, method, params);
  }

  // Evaluate a page function (or raw expression) in the page's MAIN world.
  // returnByValue serializes the result to JSON. `awaitPromise` resolves a
  // returned promise before serializing (needed for wait_for / toasts).
  // Throws on an uncaught page exception.
  async evaluate<T = unknown>(
    fnOrExpr: string | ((...args: never[]) => unknown),
    args: readonly unknown[] = [],
    opts: { awaitPromise?: boolean } = {},
  ): Promise<T> {
    const expression =
      typeof fnOrExpr === "function" ? buildEvaluateExpression(fnOrExpr, args) : fnOrExpr;
    const res = await this.send<EvaluateResponse>("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: opts.awaitPromise ?? false,
      userGesture: true,
    });
    if (res.exceptionDetails) {
      throw new Error(evalExceptionMessage(res.exceptionDetails));
    }
    return res.result?.value as T;
  }

  // Runtime.evaluate that returns the raw response (result + exceptionDetails)
  // so callers can map a page exception to structured data (page_eval).
  rawEvaluate(
    expression: string,
    opts: { awaitPromise?: boolean } = {},
  ): Promise<EvaluateResponse> {
    return this.send<EvaluateResponse>("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: opts.awaitPromise ?? false,
      userGesture: true,
    });
  }

  // Screenshot the viewport via CDP (preferred over a page-fn). Returns the
  // base64 PNG payload without the data: URL prefix, matching the content path.
  async screenshot(): Promise<{ image: string; mimeType: string }> {
    const res = await this.send<CaptureScreenshotResponse>("Page.captureScreenshot", {
      format: "png",
    });
    return { image: res.data ?? "", mimeType: "image/png" };
  }
}

export type { EvaluateResponse, ExceptionDetails };
