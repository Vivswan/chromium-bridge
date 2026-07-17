// The confirmation window (ADR-0027): an extension-owned page a guarded page
// cannot reach, read, or click. It fetches the pending payload by the id in
// its URL, renders WHAT is being approved (as text, never HTML), and reports
// the user's verdict via confirm_resolve - which the router accepts only
// from extension pages.
//
// Safety details:
// - The Allow button arms after a short delay, so a keypress or double-click
//   that was meant for something else cannot approve; Deny is instant and is
//   the default-focused control.
// - Escape denies. Closing the window denies (SW-side onRemoved).
// - The deadline is rendered as a countdown; the SW enforces it regardless.

import {
  type ConfirmKind,
  type ConfirmPayload,
  ConfirmPayloadSchema,
} from "@chromium-bridge/shared";
import { browser } from "wxt/browser";

const ARM_DELAY_MS = 600;

const QUESTIONS: Record<ConfirmKind, string> = {
  click: "Allow this click?",
  press: "Allow this keypress?",
  select: "Allow this selection?",
  eval: "Run this JavaScript on the page?",
  tab_close: "Close this tab?",
  upload: "Upload this local file to the page?",
};

const WARNINGS: Partial<Record<ConfirmKind, string>> = {
  eval: "This code runs in the page with your session. It can read tokens, cookies, and page data, and can make requests as you.",
  upload: "The file at this exact path will leave your disk and be sent to the page.",
};

function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element: ${id}`);
  return el;
}

async function resolve(id: string, approved: boolean): Promise<void> {
  try {
    await browser.runtime.sendMessage({ type: "confirm_resolve", id, approved });
  } catch {
    // SW gone; the request is already lost (denied).
  }
  window.close();
}

function render(payload: ConfirmPayload): void {
  $("question").textContent = QUESTIONS[payload.kind];
  $("origin").textContent = payload.origin;
  $("tab-title").textContent = payload.tabTitle;
  $("detail").textContent = payload.detail;
  const warn = WARNINGS[payload.kind];
  if (warn) {
    $("warn").textContent = warn;
    $("warn").style.display = "block";
  }

  const deny = $("deny") as HTMLButtonElement;
  const allow = $("allow") as HTMLButtonElement;
  deny.onclick = () => void resolve(payload.id, false);
  allow.onclick = () => void resolve(payload.id, true);
  deny.focus();
  // Arm Allow after a short delay so stray input cannot approve.
  setTimeout(() => {
    allow.disabled = false;
  }, ARM_DELAY_MS);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") void resolve(payload.id, false);
  });

  const countdown = $("countdown");
  const tick = () => {
    const left = Math.max(0, Math.ceil((payload.deadline - Date.now()) / 1000));
    countdown.textContent = `Denies automatically in ${left}s`;
    if (left > 0) setTimeout(tick, 500);
  };
  tick();
}

async function init(): Promise<void> {
  const id = new URLSearchParams(location.search).get("id") || "";
  let payload: unknown = null;
  try {
    const resp = (await browser.runtime.sendMessage({ type: "confirm_ready", id })) as
      | { payload?: unknown }
      | undefined;
    payload = resp?.payload ?? null;
  } catch {
    payload = null;
  }
  const parsed = ConfirmPayloadSchema.safeParse(payload);
  if (!parsed.success) {
    // Stale window (request already settled) or a payload that fails the
    // schema: nothing can be approved here.
    document.body.innerHTML = '<div class="gone">This confirmation is no longer pending.</div>';
    return;
  }
  render(parsed.data);
}

void init();
