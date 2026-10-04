// The pages' one way to ask the service worker anything. The answer is parsed
// against the message's declared response before a view sees it, so a view can
// only ever render a shape the contract names.

import {
  type RuntimeMsg,
  type RuntimeMsgType,
  type RuntimeResponse,
  runtimeResponseSchema,
} from "@chromium-bridge/shared/runtime-msg";
import { browser } from "wxt/browser";

export async function send<K extends RuntimeMsgType>(
  msg: RuntimeMsg & { type: K },
): Promise<RuntimeResponse<K>> {
  const type: K = msg.type;
  let raw: unknown;
  try {
    raw = await browser.runtime.sendMessage(msg);
  } catch {
    return { ok: false, error: "no answer from the service worker" };
  }
  const parsed = runtimeResponseSchema(type).safeParse(raw);
  if (!parsed.success) {
    console.error("[bb] malformed runtime response", type, parsed.error);
    return { ok: false, error: `malformed ${type} response from the service worker` };
  }
  return parsed.data;
}
