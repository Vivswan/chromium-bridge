import { useState } from "react";
import { Card, ErrorNote, Mono, StatusDot } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { api, type EnclaveOutcome, errorText } from "@/lib/tauri";

export function PairingView() {
  const { t } = useI18n();
  const enclave = useAsync(api.enclaveStatus);
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<EnclaveOutcome>();
  const [error, setError] = useState<string>();

  const run = async (action: () => Promise<EnclaveOutcome>) => {
    setBusy(true);
    setError(undefined);
    setOutcome(undefined);
    try {
      setOutcome(await action());
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
      enclave.reload();
    }
  };

  const key = enclave.data?.key;

  return (
    <div className="flex flex-col gap-4">
      <p className="m-0 text-sm text-muted">{t("pairing.intro")}</p>
      {enclave.error !== undefined && <ErrorNote>{enclave.error}</ErrorNote>}

      <Card>
        <div className="flex flex-col gap-3">
          {enclave.data !== undefined && (
            <StatusDot tone={key === "present" ? "ok" : key === "none" ? "muted" : "bad"}>
              {key === "present"
                ? t("pairing.key_present")
                : key === "none"
                  ? t("pairing.key_none")
                  : key === "unsupported"
                    ? t("pairing.key_unsupported")
                    : key === "invalid"
                      ? t("pairing.key_invalid")
                      : t("pairing.key_error")}
            </StatusDot>
          )}
          {enclave.data?.detail !== undefined && <Mono>{enclave.data.detail}</Mono>}
          {enclave.data?.fingerprint !== undefined && (
            <div className="flex flex-col gap-1">
              <span className="text-xs font-medium text-muted">{t("pairing.fingerprint")}</span>
              <Mono className="text-sm tracking-wide">{enclave.data.fingerprint}</Mono>
              <p className="m-0 text-xs text-muted">{t("pairing.compare")}</p>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            {key === "none" && (
              <Button
                variant="primary"
                disabled={busy}
                onClick={() => void run(() => api.enclavePair(false))}
              >
                {busy ? t("common.working") : t("pairing.pair")}
              </Button>
            )}
            {(key === "present" || key === "invalid" || key === "error") && (
              <>
                <Button disabled={busy} onClick={() => void run(() => api.enclavePair(true))}>
                  {busy ? t("common.working") : t("pairing.repair")}
                </Button>
                <Button variant="ghost" disabled={busy} onClick={() => void run(api.enclaveRevoke)}>
                  {t("pairing.revoke")}
                </Button>
              </>
            )}
          </div>
          <p className="m-0 text-xs text-faint">
            {key === "present" ? t("pairing.revoke_hint") : t("pairing.touch_hint")}
          </p>
        </div>
      </Card>

      {error !== undefined && <ErrorNote>{error}</ErrorNote>}
      {outcome !== undefined && (
        <Card title={t("pairing.transcript")}>
          <Mono>{outcome.transcript}</Mono>
        </Card>
      )}
    </div>
  );
}
