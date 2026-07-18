import { useEffect, useRef, useState } from "react";
import { Card, ErrorNote, Mono, StatusDot } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { authLabel } from "@/lib/auth-label";
import { api, errorText, type FirstRunReport } from "@/lib/tauri";
import { useAppStore } from "@/store";

export function OverviewView() {
  const { t } = useI18n();
  const status = useAppStore((s) => s.status);
  const statusError = useAppStore((s) => s.statusError);
  const refreshStatus = useAppStore((s) => s.refreshStatus);
  const browsers = useAsync(api.browsersList);
  const enclave = useAsync(api.enclaveStatus);

  // Self-registration on first launch (ADR-0029): the Rust side is
  // single-flight (the marker is created with create_new), and the ref keeps
  // StrictMode's double-invoked dev effect from firing the command twice.
  const [firstRun, setFirstRun] = useState<FirstRunReport | null>(null);
  const [firstRunError, setFirstRunError] = useState<string>();
  const firstRunStarted = useRef(false);
  const [busy, setBusy] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [releaseOpen, setReleaseOpen] = useState(false);
  const [releasedBy, setReleasedBy] = useState<string>();

  useEffect(() => {
    if (firstRunStarted.current) return;
    firstRunStarted.current = true;
    api
      .firstLaunchRegister()
      .then((report) => {
        setFirstRun(report);
        if (report !== null) browsers.reload();
      })
      .catch((err: unknown) => setFirstRunError(errorText(err)));
    // browsers.reload is stable (useCallback with no deps).
  }, [browsers.reload]);

  const engage = async () => {
    setBusy("engage");
    setActionError(undefined);
    setReleasedBy(undefined);
    try {
      await api.killEngage();
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setBusy(undefined);
      void refreshStatus();
    }
  };

  // Presence-gated: invoked ONLY from the confirm dialog below. The dialog
  // is what Floor::AppConfirm asserts once phase8 lands (see the Rust seam).
  const confirmRelease = async () => {
    setBusy("release");
    setActionError(undefined);
    setReleasedBy(undefined);
    try {
      const outcome = await api.killRelease();
      setReleasedBy(outcome.auth);
      setReleaseOpen(false);
    } catch (err) {
      setActionError(errorText(err));
      setReleaseOpen(false);
    } finally {
      setBusy(undefined);
      void refreshStatus();
    }
  };

  const registered = browsers.data?.filter((b) => b.detected && b.healthy).length ?? 0;
  const detected = browsers.data?.filter((b) => b.detected).length ?? 0;

  return (
    <div className="flex flex-col gap-4">
      {(firstRun !== null || firstRunError !== undefined) && (
        <Card title={t("overview.first_run_title")}>
          {firstRunError !== undefined && <ErrorNote>{firstRunError}</ErrorNote>}
          {firstRun !== null && (
            <div className="flex flex-col gap-2 text-sm text-body">
              <p className="m-0">
                {firstRun.detected.length === 0
                  ? t("overview.first_run_none")
                  : t("overview.first_run_registered")}
              </p>
              {firstRun.lines.length > 0 && <Mono>{firstRun.lines.join("\n")}</Mono>}
              {firstRun.errors.length > 0 && (
                <>
                  <p className="m-0">{t("overview.first_run_errors")}</p>
                  <ErrorNote>{firstRun.errors.join("\n")}</ErrorNote>
                </>
              )}
            </div>
          )}
        </Card>
      )}

      <Card title={t("overview.kill_title")}>
        <div className="flex flex-col gap-3">
          {statusError !== undefined && <ErrorNote>{statusError}</ErrorNote>}
          {status !== undefined &&
            (status.kill.state === "off" ? (
              <StatusDot tone="ok">{t("overview.kill_off")}</StatusDot>
            ) : status.kill.state === "engaged" ? (
              <StatusDot tone="bad">{t("overview.kill_engaged")}</StatusDot>
            ) : (
              <div className="flex flex-col gap-2">
                <StatusDot tone="warn">{t("overview.kill_unreadable")}</StatusDot>
                <Mono>{status.kill.detail}</Mono>
              </div>
            ))}
          <div className="flex items-center gap-3">
            {status?.kill.state !== "engaged" && (
              <Button variant="danger" disabled={busy !== undefined} onClick={() => void engage()}>
                {busy === "engage" ? t("common.working") : t("overview.kill_engage")}
              </Button>
            )}
            {status?.kill.state === "engaged" && (
              <Button
                variant="primary"
                disabled={busy !== undefined}
                onClick={() => setReleaseOpen(true)}
              >
                {busy === "release" ? t("common.working") : t("overview.kill_release")}
              </Button>
            )}
          </div>
          <ConfirmDialog
            open={releaseOpen}
            onOpenChange={setReleaseOpen}
            title={t("overview.kill_release_dialog_title")}
            body={t("overview.kill_release_dialog_body")}
            confirmLabel={t("overview.kill_release_confirm")}
            busy={busy === "release"}
            onConfirm={() => void confirmRelease()}
          />
          {releasedBy !== undefined && (
            <StatusDot tone="ok">{t("overview.kill_released", [authLabel(releasedBy)])}</StatusDot>
          )}
          <p className="m-0 text-xs text-muted">
            {status?.kill.state === "engaged"
              ? t("overview.kill_release_hint")
              : t("overview.kill_engage_hint")}
          </p>
          {actionError !== undefined && <ErrorNote>{actionError}</ErrorNote>}
        </div>
      </Card>

      <div className="grid grid-cols-2 gap-4">
        <Card title={t("overview.server_title")}>
          {status === undefined ? (
            <p className="m-0 text-sm text-muted">{t("common.loading")}</p>
          ) : (
            <div className="flex flex-col gap-2 text-sm">
              {status.server.lockError !== null ? (
                <StatusDot tone="warn">
                  {t("overview.server_lock_unreadable", [status.server.lockError])}
                </StatusDot>
              ) : !status.server.lockPresent ? (
                <StatusDot tone="muted">{t("overview.server_not_running")}</StatusDot>
              ) : (
                <>
                  <StatusDot tone={status.server.reachable === true ? "ok" : "warn"}>
                    {status.server.reachable === true
                      ? t("overview.server_reachable")
                      : t("overview.server_unreachable")}
                  </StatusDot>
                  {status.server.endpoint !== null && (
                    <div className="text-xs text-muted">
                      {t("overview.server_endpoint")}: <code>{status.server.endpoint}</code>
                    </div>
                  )}
                  {status.server.pid !== null && (
                    <div className="text-xs text-muted">
                      {t("overview.server_pid")}: {status.server.pid}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </Card>

        <Card title={t("overview.enclave_title")}>
          {enclave.error !== undefined ? (
            <ErrorNote>{enclave.error}</ErrorNote>
          ) : enclave.data === undefined ? (
            <p className="m-0 text-sm text-muted">{t("common.loading")}</p>
          ) : (
            <div className="flex flex-col gap-2">
              <StatusDot
                tone={
                  enclave.data.key === "present"
                    ? "ok"
                    : enclave.data.key === "none"
                      ? "muted"
                      : "bad"
                }
              >
                {enclave.data.key === "present"
                  ? t("pairing.key_present")
                  : enclave.data.key === "none"
                    ? t("pairing.key_none")
                    : enclave.data.key === "unsupported"
                      ? t("pairing.key_unsupported")
                      : enclave.data.key === "invalid"
                        ? t("pairing.key_invalid")
                        : t("pairing.key_error")}
              </StatusDot>
              {enclave.data.fingerprint !== undefined && <Mono>{enclave.data.fingerprint}</Mono>}
            </div>
          )}
        </Card>
      </div>

      <Card title={t("overview.browsers_title")}>
        {browsers.error !== undefined ? (
          <ErrorNote>{browsers.error}</ErrorNote>
        ) : (
          <StatusDot tone={registered > 0 ? "ok" : "warn"}>
            {t("overview.browsers_summary", [String(registered), String(detected)])}
          </StatusDot>
        )}
      </Card>

      {status !== undefined && (
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 px-1 text-xs text-faint">
          <span>
            {t("overview.version")}: {status.version}
          </span>
          <span>
            {t("overview.platform")}: {status.os}/{status.arch}
          </span>
          {status.hostPath !== null && (
            <span>
              {t("overview.host_title")}: <code>{status.hostPath}</code>
            </span>
          )}
        </div>
      )}
      {status?.hostError != null && <ErrorNote>{status.hostError}</ErrorNote>}
      <p className="m-0 px-1 text-xs text-faint">{t("overview.extension_note")}</p>
    </div>
  );
}
