import {
  type ConfirmKind,
  type ConfirmPayload,
  ConfirmPayloadSchema,
} from "@chromium-bridge/shared";
import { useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import type { MessageKey } from "@/lib/i18n";

// The confirmation window (ADR-0027): an extension-owned page a guarded page
// cannot reach, read, or click. It fetches the pending payload by the id in
// its URL, renders WHAT is being approved (text only), and reports the
// verdict via confirm_resolve - which the router accepts only from this exact
// document. Escape / closing the window / timeout all deny; Allow arms after
// a short delay so stray input cannot approve.

const ARM_DELAY_MS = 600;

const QUESTION_KEY: Record<ConfirmKind, MessageKey> = {
  click: "confirm.q_click",
  press: "confirm.q_press",
  select: "confirm.q_select",
  eval: "confirm.q_eval",
  tab_close: "confirm.q_tab_close",
  upload: "confirm.q_upload",
};

const WARNING_KEY: Partial<Record<ConfirmKind, MessageKey>> = {
  eval: "confirm.warn_eval",
  upload: "confirm.warn_upload",
};

async function resolve(id: string, approved: boolean): Promise<void> {
  try {
    await browser.runtime.sendMessage({ type: "confirm_resolve", id, approved });
  } catch {
    // SW gone; the request is already lost (denied).
  }
  window.close();
}

export function ConfirmApp() {
  const { t } = useI18n();
  const [payload, setPayload] = useState<ConfirmPayload | null | "loading">("loading");
  const [armed, setArmed] = useState(false);
  const [left, setLeft] = useState(0);

  useEffect(() => {
    const id = new URLSearchParams(location.search).get("id") || "";
    void browser.runtime.sendMessage({ type: "confirm_ready", id }).then(
      (resp: { payload?: unknown } | undefined) => {
        const parsed = ConfirmPayloadSchema.safeParse(resp?.payload ?? null);
        setPayload(parsed.success ? parsed.data : null);
      },
      () => setPayload(null),
    );
  }, []);

  useEffect(() => {
    if (payload === "loading" || payload === null) return;
    const armTimer = setTimeout(() => setArmed(true), ARM_DELAY_MS);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void resolve(payload.id, false);
    };
    document.addEventListener("keydown", onKey);
    const tick = () => setLeft(Math.max(0, Math.ceil((payload.deadline - Date.now()) / 1000)));
    tick();
    const countdown = setInterval(tick, 500);
    return () => {
      clearTimeout(armTimer);
      clearInterval(countdown);
      document.removeEventListener("keydown", onKey);
    };
  }, [payload]);

  if (payload === "loading") {
    return <div className="p-5 text-sm text-muted">{t("confirm.title")}</div>;
  }
  if (payload === null) {
    return <div className="p-10 text-center text-sm text-muted">{t("confirm.gone")}</div>;
  }

  const warnKey = WARNING_KEY[payload.kind];
  // ADR-0031: a hardware-gated confirmation renders display-only. Approval
  // is the Touch ID tap on the host's system prompt (the service refuses a
  // window-side approval); Deny stays - removing capability is friction-free.
  const hardware = payload.hardware === true;
  return (
    <div className="flex min-h-screen flex-col p-5">
      <h1 className="mb-0.5 text-base font-bold text-danger">{t("confirm.title")}</h1>
      <div className="mb-0.5 break-all font-mono text-xs text-muted">{payload.origin}</div>
      <div className="mb-3 truncate text-xs text-muted">{payload.tabTitle}</div>
      <div className="mb-2.5 font-semibold">{t(QUESTION_KEY[payload.kind])}</div>
      <pre className="mb-3 min-h-[60px] max-h-80 flex-1 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-edge bg-edge-soft px-3 py-2.5 font-mono text-xs">
        {payload.detail}
      </pre>
      {warnKey && <div className="mb-3 text-xs text-danger">{t(warnKey)}</div>}
      {hardware && <div className="mb-3 text-xs font-semibold">{t("confirm.touchid_wait")}</div>}
      <div className="mb-3 text-xs text-muted">{t("confirm.countdown", [String(left)])}</div>
      <div className="flex justify-end gap-2.5">
        <Button autoFocus onClick={() => void resolve(payload.id, false)}>
          {t("confirm.deny")}
        </Button>
        {!hardware && (
          <Button variant="danger" disabled={!armed} onClick={() => void resolve(payload.id, true)}>
            {t("confirm.allow")}
          </Button>
        )}
      </div>
    </div>
  );
}
