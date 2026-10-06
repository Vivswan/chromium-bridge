import type { HealthReport, RegistrationRow } from "@chromium-bridge/shared/envelope.gen";
import { BROWSER_KEYS } from "@chromium-bridge/shared/host.gen";
import type { RuntimeRequest, RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";

// The host-registration panel: the health report plain `chromium-bridge doctor` prints (rows worded by the
// host, labels localized here), then the registration rows over the SW router's two registration messages.
// Repair covers every detected
// browser, as `doctor --fix` does; a browser the host did not detect gets its own register action, as
// `--browser <key>` does. A failed repair re-asks for the rows instead of keeping the pre-repair table: the
// host answers a failure with no rows, so the rows on screen must come from a read the host vouched for.
export function RegistrationPanel() {
  const { t } = useI18n();
  const [view, setView] = useState<RuntimeResponse<"get_registration"> | null>(null);
  const [doctor, setDoctor] = useState<RuntimeResponse<"get_doctor"> | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setBusy(true);
    const [rows, report] = await Promise.all([
      send({ type: "get_registration" }),
      send({ type: "get_doctor" }),
    ]);
    setView(rows);
    setDoctor(report);
    setBusy(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // A repair changes the verdict too (a healthy registration flips `doctor` to OK), so the report is re-read
  // on either outcome.
  const repair = async (browsers?: RuntimeRequest<"repair_registration">["browsers"]) => {
    setBusy(true);
    setActionError(null);
    const r = await send(
      browsers ? { type: "repair_registration", browsers } : { type: "repair_registration" },
    );
    if (r.ok) {
      setView(r);
      setDoctor(await send({ type: "get_doctor" }));
    } else {
      setActionError(t("registration.repair_failed", [r.error]));
      await refresh();
    }
    setBusy(false);
  };

  return (
    <div className="py-1">
      <div className="flex items-start justify-between gap-3">
        <p className="consequence m-0">{t("registration.desc")}</p>
        <Button variant="ghost" onClick={() => void refresh()} disabled={busy}>
          {t("registration.refresh")}
        </Button>
      </div>

      <div className="section-title mt-3 mb-1.5">{t("doctor.title")}</div>
      {doctor === null && <div className="text-xs text-text-3">{t("doctor.loading")}</div>}
      {doctor && !doctor.ok && (
        <div role="status" className="text-xs font-semibold text-pending">
          {t("doctor.error", [doctor.error])}
        </div>
      )}
      {doctor?.ok && <HealthRows report={doctor.report} />}

      <div className="section-title mt-5 mb-1.5">{t("registration.rows_title")}</div>
      {view === null && <div className="mt-2 text-xs text-text-3">{t("registration.loading")}</div>}

      {/* A read failure is unknown/degraded, not a denial: pending ink, fail-closed wording. */}
      {view && !view.ok && (
        <div role="status" className="mt-2 text-xs font-semibold text-pending">
          {t("registration.error", [view.error])}
        </div>
      )}

      {view?.ok && view.browsers.length === 0 && (
        <div className="mt-2 text-xs text-text-3">{t("registration.empty")}</div>
      )}

      {view?.ok && view.browsers.length > 0 && (
        <ul className="m-0 mt-1 list-none p-0">
          {view.browsers.map((row) => (
            <RegistrationLine
              key={row.browser}
              row={row}
              busy={busy}
              onRegister={(browser) => void repair([browser])}
            />
          ))}
        </ul>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <Button onClick={() => void repair()} disabled={busy || view === null || !view.ok}>
          {t("registration.repair")}
        </Button>
        <span className="text-[11px] text-text-3">{t("registration.restart_note")}</span>
      </div>
      <p className="consequence mt-2">{t("registration.cli_only_note")}</p>

      <div
        role="alert"
        className={actionError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
      >
        {actionError}
      </div>
    </div>
  );
}

function HealthRows({ report }: { report: HealthReport }) {
  const { t } = useI18n();
  const rows = [
    { label: t("doctor.lock_file"), row: report.lock_file },
    { label: t("doctor.mcp_server"), row: report.mcp_server },
    { label: t("doctor.kill_switch"), row: report.kill_switch },
    { label: t("doctor.policy_baseline"), row: report.policy_baseline },
  ];
  return (
    <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 font-mono text-[11px]">
      <dt className="text-text-3">{t("doctor.version")}</dt>
      <dd className="m-0 text-text-1">
        {report.version} ({report.platform})
      </dd>
      {rows.map(({ label, row }) => (
        <HealthRow key={label} label={label} row={row} />
      ))}
      <dt className="text-text-3">{t("doctor.summary")}</dt>
      <dd className="m-0 flex items-center gap-2 font-semibold text-text-1">
        <span className={`status-dot ${report.healthy ? "live" : "down"}`} />
        {report.summary}
      </dd>
    </dl>
  );
}

function HealthRow({ label, row }: { label: string; row: HealthReport["lock_file"] }) {
  return (
    <>
      <dt className="text-text-3">{label}</dt>
      <dd className="m-0 break-all text-text-1">
        {row.value}
        {row.details.map((detail) => (
          <div key={detail} className="whitespace-pre-wrap text-text-3">
            {detail}
          </div>
        ))}
      </dd>
    </>
  );
}

function RegistrationLine({
  row,
  busy,
  onRegister,
}: {
  row: RegistrationRow;
  busy: boolean;
  onRegister: (browser: (typeof BROWSER_KEYS)[number]) => void;
}) {
  const { t } = useI18n();
  const healthy = row.state.kind === "ok";
  const detail = row.state.kind === "ok" || row.state.kind === "missing" ? null : row.state.detail;
  // The bulk repair skips an undetected browser, so that row offers the CLI's `--browser` form; only a key
  // the generated list knows can be named, which the host's rows always carry.
  const key = BROWSER_KEYS.find((known) => known === row.browser);
  return (
    <li className="flex items-start gap-3 border-b border-edge py-2 last:border-b-0">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className={`status-dot ${healthy ? "live" : row.detected ? "down" : ""}`} />
          <span className="font-mono text-xs font-semibold text-text-1">{row.browser}</span>
          <span className="text-[11px] text-text-3">
            {row.detected ? t("registration.detected") : t("registration.not_detected")}
          </span>
          <span
            className={`text-[11px] font-semibold ${healthy ? "text-text-2" : row.detected ? "text-danger" : "text-text-3"}`}
          >
            {t(`registration.state_${row.state.kind}`)}
          </span>
        </div>
        {detail && <div className="mt-0.5 font-mono text-[11px] text-text-3">{detail}</div>}
        <div className="truncate font-mono text-[11px] text-text-4" title={row.location}>
          {row.location}
        </div>
      </div>
      {!row.detected && key !== undefined && (
        <Button variant="ghost" onClick={() => onRegister(key)} disabled={busy}>
          {t("registration.register_one", [row.browser])}
        </Button>
      )}
    </li>
  );
}
