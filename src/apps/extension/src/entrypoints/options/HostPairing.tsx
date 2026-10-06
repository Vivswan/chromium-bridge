import type { EnrollmentActionType, RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import type { ReactNode } from "react";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import type { MessageKey } from "@/lib/i18n";
import { send } from "@/lib/messages";

// The host-key pairing block of the identity panel. Event-driven: the enclave-* storage keys change
// when a proof/error frame lands in the background, so this refreshes on
// storage.onChanged instead of polling. Every action
// (pair/verify/approve/reject/revoke) also refreshes on return.
//
// Control Tower: open rows, no card chrome. The pending fingerprint renders
// as two open columns - what this extension sees vs. what the terminal
// printed - with the extension's side marked in amber (waiting on you).
export function HostPairing() {
  const { t } = useI18n();
  // null until the first answer lands; a refusal renders the no-status line.
  const [st, setSt] = useState<RuntimeResponse<"get_enrollment"> | null>(null);
  // The host key's `key:` line as `chromium-bridge enclave-status` prints it (its state, and where it
  // lives), read with the pairing status: a refusal shows nothing, since the pin above is the extension's
  // own fact and the key line is the host's.
  const [hostKey, setHostKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [status, doctor] = await Promise.all([
      send({ type: "get_enrollment" }),
      send({ type: "get_doctor" }),
    ]);
    setSt(status);
    setHostKey(doctor.ok ? doctor.report.host_key : null);
  }, []);

  useEffect(() => {
    void refresh();
    const onChange = (changes: Record<string, unknown>, area: string) => {
      // The ceremony writes these keys.
      const keys = [
        "enclavePin",
        "enclavePending",
        "enclaveCompromised",
        "enclaveLastError",
        "enclaveLastVerifiedAt",
        "enclaveHostRevokePending",
      ];
      if (area === "local" && keys.some((k) => k in changes)) void refresh();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => browser.storage.onChanged.removeListener(onChange);
  }, [refresh]);

  const act = async (type: EnrollmentActionType, confirmKey?: MessageKey) => {
    if (confirmKey && !window.confirm(t(confirmKey))) return;
    await send({ type });
    void refresh();
  };

  const fmtDate = (ms?: number) => (ms ? new Date(ms).toLocaleString() : "");

  if (st === null) return <div className="py-2 text-xs text-text-3">{t("enroll.loading")}</div>;
  if (!st.ok) {
    return <div className="py-2 text-xs font-semibold text-danger">{t("enroll.no_status")}</div>;
  }

  return (
    <div className="py-1">
      {st.state === "pinned" && (
        <>
          <div className="flex items-center gap-2 text-[13px] font-medium">
            <span className="status-dot live" />
            {t("enroll.state_pinned")}
          </div>
          {st.fingerprint && (
            <div className="mt-2 break-all font-mono text-[13px] font-medium tracking-[0.06em] text-text-1">
              {st.fingerprint}
            </div>
          )}
          <div className="tnum mt-1.5 font-mono text-[11px] text-text-3">
            {st.pinnedAt ? `${t("enroll.pinned_at", [fmtDate(st.pinnedAt)])} - ` : ""}
            {st.lastVerifiedAt
              ? t("enroll.last_verified", [fmtDate(st.lastVerifiedAt)])
              : t("enroll.never_verified")}
          </div>
          <Actions>
            <Button onClick={() => void act("enroll_verify")}>{t("enroll.btn_verify")}</Button>
            <Button
              variant="ghost"
              onClick={() => void act("enroll_revoke", "enroll.confirm_revoke")}
            >
              {t("enroll.btn_revoke")}
            </Button>
          </Actions>
        </>
      )}

      {st.state === "pending" && (
        <>
          <div className="flex items-center gap-2 text-[13px] font-medium">
            {t("enroll.state_pending")}
            <span className="pill pill-pending">
              <span className="status-dot pending" />
              {t("enroll.pill_pending")}
            </span>
          </div>
          <div className="mt-3 grid grid-cols-1 gap-5 sm:grid-cols-2">
            <div>
              <div className="section-title mb-1.5 text-pending">{t("enroll.col_extension")}</div>
              <div className="break-all font-mono text-sm font-medium tracking-[0.06em] text-text-1">
                {st.fingerprint}
              </div>
            </div>
            <div>
              <div className="section-title mb-1.5">{t("enroll.col_terminal")}</div>
              <div className="text-xs text-text-3">{t("enroll.col_terminal_hint")}</div>
            </div>
          </div>
          <p className="consequence mt-3">{t("enroll.pending_desc")}</p>
          <Actions>
            <Button variant="primary" onClick={() => void act("enroll_reject")}>
              {t("enroll.btn_reject")}
            </Button>
            <Button onClick={() => void act("enroll_approve")}>{t("enroll.btn_approve")}</Button>
          </Actions>
        </>
      )}

      {st.state === "compromised" && (
        <>
          <div className="flex items-center gap-2 text-[13px] font-semibold text-danger">
            <span className="status-dot down" />
            {t("enroll.state_compromised")}
          </div>
          {st.compromisedReason && (
            <div className="mt-1 font-mono text-xs text-danger">{st.compromisedReason}</div>
          )}
          <p className="consequence mt-1">{t("enroll.compromised_desc")}</p>
          <Actions>
            <Button
              variant="ghost"
              onClick={() => void act("enroll_revoke", "enroll.confirm_revoke_compromised")}
            >
              {t("enroll.btn_revoke")}
            </Button>
          </Actions>
        </>
      )}

      {st.state === "unpaired" && (
        // Enrollment is required, there is no opt-out, so the unpaired state on
        // a capable platform always blocks the bridge: the page's recovery
        // hero, amber (waiting on you), with the unblocking action right here.
        <div className="rounded-lg border border-pending-edge bg-pending-dim px-3.5 py-3">
          <div className="flex items-center gap-2 text-[13px] font-semibold">
            <span className="status-dot pending" />
            {t("enroll.unpaired_hero_title")}
          </div>
          <p className="consequence mt-1">{t("enroll.unpaired_blocked")}</p>
          <Actions>
            <Button variant="pending" onClick={() => void act("enroll_pair")}>
              {t("enroll.btn_pair")}
            </Button>
          </Actions>
        </div>
      )}

      {hostKey !== null && (
        <div className="mt-2 font-mono text-[11px] text-text-3">
          {t("enroll.host_key_line", [hostKey])}
        </div>
      )}

      {st.hostRevokePending && (
        <div className="mt-2 text-xs text-text-3">{t("enroll.host_revoke_pending")}</div>
      )}

      <div
        role="alert"
        className={st.lastError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
      >
        {st.lastError}
      </div>
    </div>
  );
}

function Actions({ children }: { children: ReactNode }) {
  return <div className="mt-3 flex flex-wrap gap-2">{children}</div>;
}
