// Deadline helpers for the raw DevTools (CDP) handshake of the browser suites.

/** One entry of Chrome's `/json/list`; only the fields the suites read. */
export interface DevToolsTarget {
  id: string;
  type: string;
}

/** Bound `promise` to `ms`, rejecting with a message that names the phase. */
export function withDeadline<T>(promise: Promise<T>, ms: number, phase: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${phase} timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

const POLL_INTERVAL_MS = 100;

/**
 * Headless Chrome answers `/json/version` before its initial tab shows up in
 * `/json/list`, so one read right after readiness can find no page target.
 */
export async function waitForPageTarget(port: number, deadlineMs: number): Promise<DevToolsTarget> {
  const deadline = Date.now() + deadlineMs;
  let polls = 0;
  let lastTypes: string[] | undefined;
  let cutOff: unknown;
  for (;;) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    let targets: DevToolsTarget[];
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`, {
        signal: AbortSignal.timeout(remaining),
      });
      if (!res.ok) throw new Error(`/json/list answered HTTP ${res.status}`);
      targets = (await res.json()) as DevToolsTarget[];
    } catch (e) {
      if (!(e instanceof DOMException && e.name === "TimeoutError")) throw e;
      cutOff = e;
      break;
    }
    polls++;
    lastTypes = targets.map((t) => t.type);
    const page = targets.find((t) => t.type === "page");
    if (page) return page;
    await Bun.sleep(Math.min(POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
  }
  const seen =
    lastTypes === undefined
      ? "/json/list never answered"
      : `${polls} polls of /json/list; last listed types: [${lastTypes.join(", ")}]`;
  throw new Error(`no DevTools page target on port ${port} within ${deadlineMs}ms (${seen})`, {
    cause: cutOff,
  });
}
