// console_get — read recent console output from the active tab via Chrome's
// debugger (CDP). We attach, enable Runtime + Log, collect the events the
// browser delivers during a short window (Log.enable replays buffered
// browser-side entries; Runtime.consoleAPICalled and Runtime.exceptionThrown
// arrive for anything happening while we listen), then detach. Console.* output
// produced before the call is generally NOT available — the DevTools protocol
// does not replay historical console.* calls — so this is honest about only
// surfacing what the debugger reports at call time. Values are masked before
// they leave the extension (console lines can carry tokens). Mirrors the
// transient-attach shape of precise.ts (ADR-0009 / ADR-0017).

import type { Browser } from "wxt/browser";
import { browser } from "wxt/browser";
import { maskString } from "../shared/masking";
import type { OpArgs } from "../shared/types";
import { ensureAllowed } from "./allowlist-store";
import { cdpRegistry } from "./cdp/registry";
import { dbgAttach, dbgDetach, dbgSend, isDebuggable } from "./cdp/session";
import { resolveTargetTab } from "./tabs";

// The subset of CDP payloads we read (not the full protocol).
interface RemoteObject {
  type?: string;
  value?: unknown;
  description?: string;
  unserializableValue?: string;
}
interface ConsoleApiCalled {
  type?: string;
  args?: RemoteObject[];
}
interface LogEntry {
  level?: string;
  text?: string;
  source?: string;
  url?: string;
}
interface ExceptionThrown {
  exceptionDetails?: { text?: string; exception?: RemoteObject };
}

interface ConsoleLine {
  level: string;
  text: string;
  source?: string;
  url?: string;
}

// Preview a Runtime.RemoteObject argument as a short string for the console line.
function previewArg(a: RemoteObject): string {
  if (a == null) return "";
  if (a.value !== undefined) {
    try {
      return typeof a.value === "string" ? a.value : JSON.stringify(a.value);
    } catch {
      return String(a.value);
    }
  }
  if (a.unserializableValue) return a.unserializableValue;
  if (a.description) return a.description;
  return a.type || "";
}

export async function consoleGet(maybeTabId: number | undefined, args: OpArgs): Promise<unknown> {
  const tab = await resolveTargetTab(maybeTabId);
  await ensureAllowed(tab.url);
  if (!isDebuggable(tab.url)) {
    throw new Error(
      `console_get cannot debug this page (URL scheme not allowed): ${(tab.url || "").slice(0, 80)}`,
    );
  }
  const tabId = tab.id!;
  const limit =
    typeof args.limit === "number" && args.limit > 0 ? Math.min(Math.floor(args.limit), 1000) : 100;

  const collected: ConsoleLine[] = [];
  const onEvent = (source: Browser.debugger.Debuggee, method: string, params?: object): void => {
    if (source.tabId !== tabId) return;
    if (method === "Runtime.consoleAPICalled") {
      const e = params as ConsoleApiCalled;
      collected.push({
        level: e.type || "log",
        text: (e.args || []).map(previewArg).join(" "),
        source: "console-api",
      });
    } else if (method === "Log.entryAdded") {
      const entry = (params as { entry?: LogEntry }).entry || {};
      collected.push({
        level: entry.level || "info",
        text: entry.text || "",
        source: entry.source,
        url: entry.url,
      });
    } else if (method === "Runtime.exceptionThrown") {
      const details = (params as ExceptionThrown).exceptionDetails || {};
      const desc = details.exception?.description || details.text || "Uncaught exception";
      const firstLine = String(desc).split("\n")[0] ?? String(desc);
      collected.push({ level: "error", text: firstLine, source: "exception" });
    }
  };

  // Reuse the persistent CDP-mode attach if present (a second attach would
  // fail); only tear down what we set up ourselves.
  const reusing = cdpRegistry.hasSession(tabId);
  browser.debugger.onEvent.addListener(onEvent);
  try {
    if (reusing) {
      // Await the registry's idempotent (de-duped) attach so we never issue CDP
      // commands before a still-in-flight persistent attach has completed.
      await cdpRegistry.get(tabId);
    } else {
      await dbgAttach(tabId);
    }
  } catch (e) {
    browser.debugger.onEvent.removeListener(onEvent);
    const msg = String((e as Error).message || e);
    if (/another debugger/i.test(msg)) {
      throw new Error(
        "console_get cannot attach: DevTools is open on this tab. Close DevTools and retry.",
        {
          cause: e,
        },
      );
    }
    throw e;
  }
  try {
    await dbgSend(tabId, "Runtime.enable", {});
    await dbgSend(tabId, "Log.enable", {});
    // Give the browser a brief window to replay buffered Log entries and to
    // deliver any console.* calls / exceptions happening right now.
    await new Promise((r) => setTimeout(r, 400));
  } finally {
    browser.debugger.onEvent.removeListener(onEvent);
    if (!reusing) {
      // Best-effort cleanup: never throw from teardown.
      await dbgSend(tabId, "Runtime.disable", {}).catch(() => {});
      await dbgSend(tabId, "Log.disable", {}).catch(() => {});
      await dbgDetach(tabId);
    }
  }

  const truncated = collected.length > limit;
  // Mask both the message text AND the per-entry url: a Log entry's url is the
  // resource that logged it and can carry access tokens / signed query params /
  // auth codes. maskString is a no-op on a benign URL, so this never over-redacts.
  const entries = collected.slice(-limit).map((line) => ({
    level: line.level,
    text: maskString(line.text),
    source: line.source,
    url: line.url ? maskString(line.url) : line.url,
  }));
  return { count: entries.length, entries, truncated, url: maskString(tab.url || "") };
}
