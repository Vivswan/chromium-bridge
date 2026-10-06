import type {
  EnrollOptionsFrame,
  PresenceRequestFrame,
} from "@chromium-bridge/shared/envelope.gen";
import { type RuntimeResponse, WEBAUTHN_ENROLLMENT_KEY } from "@chromium-bridge/shared/runtime-msg";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";
import { assert, register } from "@/lib/shared/webauthn-ceremony";
import { ceremonyFailure, refusalSentence } from "./refusals";

// This browser's WebAuthn enrollment: the worker's note of the last credential enrolled here, and the ceremony
// that enrolls one. The host decides everything (src/packages/core/src/native_host/presence.rs); this page
// runs the two `navigator.credentials` calls it cannot and shows each step.
//
//   fresh machine        enroll_begin -> options -> create -> enroll_finish -> enrolled
//   enrolled machine     enroll_begin -> presence_required; the pushed request is shown and the user approves it
//                        with an authenticator already enrolled here; the approved tap is good for 60 s, so the
//                        page asks again at once and the ceremony continues as above
//   forget               webauthn_forget -> the host forgets this browser's credentials (its own label, no proof)
//                        and the worker clears its note; the same act as `chromium-bridge revoke <browser>`
//
// Every refusal is one sentence (refusals.ts), never a raw code.

type Step =
  | { kind: "idle" }
  | { kind: "asking" }
  | { kind: "creating" }
  | { kind: "approval_needed"; request: PresenceRequestFrame }
  | { kind: "approving" }
  | { kind: "enrolled" }
  | { kind: "refused"; reason: string }
  | { kind: "forgetting" }
  | { kind: "forgotten" }
  | { kind: "forget_refused"; reason: string };

const BUSY: ReadonlySet<Step["kind"]> = new Set(["asking", "creating", "approving", "forgetting"]);

export function AuthenticatorEnrollment() {
  const { t } = useI18n();
  const [note, setNote] = useState<RuntimeResponse<"webauthn_enrollment"> | null>(null);
  const [step, setStep] = useState<Step>({ kind: "idle" });

  const refresh = useCallback(async () => {
    setNote(await send({ type: "webauthn_enrollment" }));
  }, []);

  useEffect(() => {
    void refresh();
    const onChanged = (changes: Record<string, unknown>, area: string) => {
      if (area === "local" && WEBAUTHN_ENROLLMENT_KEY in changes) void refresh();
    };
    browser.storage.onChanged.addListener(onChanged);
    return () => browser.storage.onChanged.removeListener(onChanged);
  }, [refresh]);

  const create = async (options: EnrollOptionsFrame) => {
    setStep({ kind: "creating" });
    let response: Awaited<ReturnType<typeof register>>;
    try {
      response = await register(options);
    } catch (e) {
      setStep({ kind: "refused", reason: ceremonyFailure(e) });
      return;
    }
    const finished = await send({ type: "webauthn_enroll_finish", ...response });
    setStep(finished.ok ? { kind: "enrolled" } : { kind: "refused", reason: finished.error });
  };

  const enroll = async () => {
    setStep({ kind: "asking" });
    const begun = await send({ type: "webauthn_enroll_begin" });
    if (begun.ok) {
      await create(begun.options);
      return;
    }
    if (begun.error !== "presence_required") {
      setStep({ kind: "refused", reason: begun.error });
      return;
    }
    // The host pushed its request before this refusal, so the worker holds it already.
    const pending = await send({ type: "webauthn_presence_pending" });
    if (pending.ok && pending.request) {
      setStep({ kind: "approval_needed", request: pending.request });
      return;
    }
    setStep({ kind: "refused", reason: pending.ok ? begun.error : pending.error });
  };

  const approve = async (request: PresenceRequestFrame) => {
    setStep({ kind: "approving" });
    let response: Awaited<ReturnType<typeof assert>>;
    try {
      response = await assert(request);
    } catch (e) {
      setStep({ kind: "refused", reason: ceremonyFailure(e) });
      return;
    }
    const verdict = await send({
      type: "webauthn_presence_assert",
      nonce: request.nonce,
      ...response,
    });
    if (!verdict.ok) {
      setStep({ kind: "refused", reason: verdict.error });
      return;
    }
    // The host holds the approval for the next enroll_begin, so ask now rather than wait for a second press.
    await enroll();
  };

  const forget = async () => {
    if (!window.confirm(t("webauthn.forget_confirm"))) return;
    setStep({ kind: "forgetting" });
    const r = await send({ type: "webauthn_forget" });
    setStep(r.ok ? { kind: "forgotten" } : { kind: "forget_refused", reason: r.error });
  };

  const enrolled = note?.ok === true && note.enrollment !== null;
  const refusal =
    step.kind === "refused"
      ? t("webauthn.failed", [refusalSentence(t, step.reason)])
      : step.kind === "forget_refused"
        ? t("webauthn.forget_failed", [refusalSentence(t, step.reason)])
        : null;
  const busy = BUSY.has(step.kind);

  return (
    <div className="py-1">
      <p className="consequence">{t("webauthn.desc")}</p>

      {note === null && <div className="mt-2 text-xs text-text-3">{t("webauthn.loading")}</div>}
      {note !== null && !note.ok && (
        <div className="mt-2 text-xs font-semibold text-danger">
          {t("webauthn.no_status", [note.error])}
        </div>
      )}
      {note?.ok && note.enrollment === null && (
        <div className="mt-2 flex items-center gap-2 text-[13px] font-medium">
          <span className="status-dot" />
          {t("webauthn.state_none")}
        </div>
      )}
      {note?.ok && note.enrollment !== null && (
        <>
          <div className="mt-2 flex items-center gap-2 text-[13px] font-medium">
            <span className="status-dot live" />
            {t("webauthn.state_enrolled", [new Date(note.enrollment.enrolledAt).toLocaleString()])}
          </div>
          <div className="mt-1 break-all font-mono text-[11px] text-text-3">
            {note.enrollment.credentialId}
          </div>
        </>
      )}

      {step.kind === "approval_needed" && (
        <div className="mt-3 rounded-lg border border-pending-edge bg-pending-dim px-3.5 py-3">
          <div className="flex items-center gap-2 text-[13px] font-semibold">
            <span className="status-dot pending" />
            {t("webauthn.approval_title")}
          </div>
          <p className="consequence mt-1">{t("webauthn.approval_desc")}</p>
          <div className="mt-2 font-mono text-xs text-text-2">
            {t("webauthn.approval_action", [step.request.action])}
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="pending" onClick={() => void approve(step.request)}>
              {t("webauthn.btn_approve")}
            </Button>
            <Button variant="ghost" onClick={() => setStep({ kind: "idle" })}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      )}

      {busy && (
        <div role="status" className="mt-2 text-xs text-text-3">
          {step.kind === "asking" && t("webauthn.step_asking")}
          {step.kind === "creating" && t("webauthn.step_creating")}
          {step.kind === "approving" && t("webauthn.step_approving")}
          {step.kind === "forgetting" && t("webauthn.step_forgetting")}
        </div>
      )}
      {step.kind === "enrolled" && (
        <div role="status" className="mt-2 text-xs font-semibold">
          {t("webauthn.enrolled_now")}
        </div>
      )}
      {step.kind === "forgotten" && (
        <div role="status" className="mt-2 text-xs font-semibold">
          {t("webauthn.forgotten_now")}
        </div>
      )}
      <div role="alert" className={refusal ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}>
        {refusal}
      </div>

      {step.kind !== "approval_needed" && (
        <div className="mt-3 flex flex-wrap gap-2">
          <Button
            variant={enrolled ? "default" : "pending"}
            disabled={busy || note === null}
            onClick={() => void enroll()}
          >
            {t(enrolled ? "webauthn.btn_enroll_another" : "webauthn.btn_enroll")}
          </Button>
          {enrolled && (
            <Button variant="ghost" disabled={busy} onClick={() => void forget()}>
              {t("webauthn.btn_forget")}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
