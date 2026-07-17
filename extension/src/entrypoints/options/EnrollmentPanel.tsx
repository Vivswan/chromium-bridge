import type { ReactNode } from "react";
import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import type { MessageKey } from "@/lib/i18n";
import { type EnrollmentStatusView, send } from "@/lib/messages";

// The ADR-0021 pairing ceremony panel. Event-driven: the enclave-* storage
// keys change when a proof/error frame lands in the background, so this
// refreshes on storage.onChanged instead of the old 2s poll. Every action
// (pair/verify/approve/reject/revoke) also refreshes on return.
export function EnrollmentPanel() {
  const { t } = useI18n();
  const [st, setSt] = useState<EnrollmentStatusView | undefined | null>(null);

  const refresh = useCallback(async () => {
    setSt((await send<EnrollmentStatusView>({ type: "get_enrollment" })) ?? undefined);
  }, []);

  useEffect(() => {
    void refresh();
    const onChange = (changes: Record<string, unknown>, area: string) => {
      // The ceremony writes these keys; requireEnrollment affects the panel too.
      const keys = [
        "enclavePin",
        "enclavePending",
        "enclaveCompromised",
        "enclaveLastError",
        "enclaveLastVerifiedAt",
        "requireEnrollment",
      ];
      if (area === "local" && keys.some((k) => k in changes)) void refresh();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => browser.storage.onChanged.removeListener(onChange);
  }, [refresh]);

  const act = async (type: string, confirmKey?: MessageKey) => {
    if (confirmKey && !window.confirm(t(confirmKey))) return;
    await send({ type });
    void refresh();
  };

  const fmtDate = (ms?: number) => (ms ? new Date(ms).toLocaleString() : "");

  if (st === null)
    return (
      <div className="rounded-xl border border-edge p-3.5 text-muted">{t("enroll.loading")}</div>
    );
  if (st === undefined) {
    return (
      <div className="rounded-xl border border-danger p-3.5 text-danger-strong">
        {t("enroll.no_status")}
      </div>
    );
  }

  // Platform without a Secure Enclave: show the N/A panel, but still surface a
  // compromised state (which blocks regardless of platform) with its revoke.
  if (!st.platformSupported && st.state !== "compromised") {
    return (
      <div className="rounded-xl border border-edge p-3.5">
        <div className="font-semibold">{t("enroll.na_title")}</div>
        <div className="mt-1 text-xs text-muted">{t("enroll.na_desc")}</div>
      </div>
    );
  }

  const Fingerprint = st.fingerprint ? (
    <div className="my-2 break-all rounded-lg border border-edge bg-edge-soft px-3 py-2.5 font-mono text-[13px] tracking-wide">
      {st.fingerprint}
    </div>
  ) : null;

  return (
    <div className="rounded-xl border border-edge p-3.5">
      {st.state === "pinned" && (
        <>
          <div className="font-semibold text-brand">{t("enroll.state_pinned")}</div>
          {Fingerprint}
          <div className="text-xs text-muted">
            {st.pinnedAt ? `${t("enroll.pinned_at", [fmtDate(st.pinnedAt)])} - ` : ""}
            {st.lastVerifiedAt
              ? t("enroll.last_verified", [fmtDate(st.lastVerifiedAt)])
              : t("enroll.never_verified")}
          </div>
          <Actions>
            <Button variant="primary" onClick={() => void act("enroll_verify")}>
              {t("enroll.btn_verify")}
            </Button>
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
          <div className="font-semibold text-danger">{t("enroll.state_pending")}</div>
          {Fingerprint}
          <div className="text-xs text-muted">{t("enroll.pending_desc")}</div>
          <Actions>
            <Button variant="primary" onClick={() => void act("enroll_approve")}>
              {t("enroll.btn_approve")}
            </Button>
            <Button variant="ghost" onClick={() => void act("enroll_reject")}>
              {t("enroll.btn_reject")}
            </Button>
          </Actions>
        </>
      )}

      {st.state === "compromised" && (
        <>
          <div className="font-semibold text-danger">{t("enroll.state_compromised")}</div>
          {st.compromisedReason && (
            <div className="mt-1 text-xs font-semibold text-danger-strong">
              {st.compromisedReason}
            </div>
          )}
          <div className="mt-1 text-xs text-muted">{t("enroll.compromised_desc")}</div>
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
        <>
          <div className={st.required ? "font-semibold text-danger" : "font-semibold"}>
            {t("enroll.state_unpaired")}
          </div>
          <div className="mt-1 text-xs text-muted">
            {st.required ? t("enroll.unpaired_blocked") : t("enroll.unpaired_unblocked")}
          </div>
          <Actions>
            <Button variant="primary" onClick={() => void act("enroll_pair")}>
              {t("enroll.btn_pair")}
            </Button>
          </Actions>
        </>
      )}

      {st.lastError && (
        <div className="mt-2 text-xs font-semibold text-danger-strong">{st.lastError}</div>
      )}
    </div>
  );
}

function Actions({ children }: { children: ReactNode }) {
  return <div className="mt-3 flex flex-wrap gap-2">{children}</div>;
}
