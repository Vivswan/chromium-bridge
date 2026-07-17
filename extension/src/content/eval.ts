// page_eval (high-risk, ADR-0008) — execute arbitrary JS in the page's global
// scope after an enlarged confirmation toast. Result is safely serialized and
// (by default) masked before returning.

import { maskSensitive } from "../shared/masking";
import { getSetting } from "../shared/settings";
import type { OpArgs } from "../shared/types";
import { confirmWithEvalToast } from "./toast";
import { truncate } from "./util";

export async function runEval(args: OpArgs) {
  const code = args.code;
  if (typeof code !== "string" || !code.trim()) {
    throw new Error("page_eval needs non-empty `code`");
  }
  // Global kill switch: if the user disabled page_eval in settings, refuse
  // before any code runs (and before any confirmation prompt).
  const evalEnabled = await getSetting("pageEvalEnabled");
  if (evalEnabled === false) {
    throw new Error("page_eval disabled in settings");
  }
  // Confirm with the user via an enlarged Toast showing the full code, unless
  // the user turned the eval confirmation off (confirmPageEval=false) for
  // hands-off automation. Every page_eval reconfirms: unlike click/submit,
  // eval is excluded from the same-origin grace window, so there is no silent-
  // eval window (ADR-0008 update 2026-07-16). NOTE: this confirmation is
  // ADR-0008's guardrail - disabling it means arbitrary JS runs with no prompt.
  if ((await getSetting("confirmPageEval")) !== false) {
    await confirmWithEvalToast(code);
  }
  // The mask gate applies to EVERY egress path below - the success value, a
  // thrown exception, and a failure inside serialization. Exceptions used to
  // bypass it, so `throw new Error(localStorage.authToken)` carried the secret
  // out around the mask.
  const mask = (await getSetting("evalMask")) !== false;
  const guard = (v: unknown) => (mask ? maskSensitive(v) : v);
  // Execute. Wrap as an async IIFE in the global scope so the code can use
  // await/return and see page globals. `new Function` (not eval) gives us
  // global scope regardless of the strict-mode closure this file runs in.
  try {
    const fn = new Function(`"use strict";\nreturn (async () => {\n${code}\n})();`);
    const result = await fn();
    // Serialize inside the try: a getter that throws during serialization must
    // land in the catch below, not escape unmasked to the outer handler.
    return guard(serializeResult(result));
  } catch (e) {
    // Surface JS errors to the model as structured data, not a throw, so the
    // model can react (e.g. fix the code and retry).
    const err = e as { name?: unknown; message?: unknown; stack?: unknown } | null | undefined;
    return guard({
      __evalError: true,
      name: String(err?.name || "Error"),
      message: String(err?.message || e),
      stack: truncate(String(err?.stack || ""), 2000),
    });
  }
}

// Safe serialization: handles cycles, DOM nodes, errors, exotic types, and
// truncates very large payloads. Returns JSON-serializable data.
function serializeResult(value: unknown, seen = new WeakSet<object>(), depth = 0): unknown {
  if (depth > 50) return "[depth limit]";
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return truncate(value, 10000);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return `[BigInt:${value.toString()}]`;
  if (typeof value === "symbol") return `[Symbol:${value.toString()}]`;
  if (typeof value === "function") return `[function:${value.name || "anonymous"}]`;
  if (typeof value === "object") {
    // Error → structured
    if (value instanceof Error) {
      return { __error: true, name: value.name, message: value.message };
    }
    // DOM node → short tag descriptor
    if (value instanceof Element) {
      const id = value.id ? `#${value.id}` : "";
      return `<${value.tagName.toLowerCase()}${id}>`;
    }
    if (value instanceof Node) {
      return `<${value.nodeName}>`;
    }
    // Cycle guard
    if (seen.has(value)) return "[Circular]";
    seen.add(value);
    try {
      if (Array.isArray(value)) {
        if (value.length > 1000) return `[Array length=${value.length}, truncated]`;
        return value.slice(0, 1000).map((v) => serializeResult(v, seen, depth + 1));
      }
      // Plain object: enumerate own keys. Map/Set/Date get special tags.
      if (value instanceof Map) {
        const obj: Record<string, unknown> = {};
        let i = 0;
        for (const [k, v] of value) {
          obj[String(k)] = serializeResult(v, seen, depth + 1);
          if (++i > 1000) break;
        }
        return { __Map: obj };
      }
      if (value instanceof Set) {
        return {
          __Set: Array.from(value)
            .slice(0, 1000)
            .map((v) => serializeResult(v, seen, depth + 1)),
        };
      }
      if (value instanceof Date) return { __Date: value.toISOString() };
      if (value instanceof RegExp) return { __RegExp: value.toString() };
      const rec = value as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      let count = 0;
      for (const key of Object.keys(rec)) {
        if (count++ > 1000) {
          out.__truncated = true;
          break;
        }
        out[key] = serializeResult(rec[key], seen, depth + 1);
      }
      return out;
    } finally {
      seen.delete(value);
    }
  }
  return String(value);
}
