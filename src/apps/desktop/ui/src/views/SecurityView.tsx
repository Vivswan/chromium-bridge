import {
  Consequence,
  Dot,
  ErrorNote,
  Pill,
  SpecLabel,
  TouchIdChip,
  TouchIdIcon,
  ViewShell,
} from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { api } from "@/lib/tauri";
import { useAppStore } from "@/store";

// The Security screen shows policy as it is enforced TODAY. Client
// admission and the presence gates are host-side facts; capability grants
// and per-tool confirmation policy still live in the extension (they move
// host-side in a later protocol phase), so those sections carry a quiet
// pointer instead of dead controls - a toggle that does nothing is a lie.
export function SecurityView() {
  const { t } = useI18n();
  const status = useAppStore((s) => s.status);
  const setView = useAppStore((s) => s.setView);
  const enclave = useAsync(api.enclaveStatus);
  const clients = useAsync(api.clientsList);

  const keyPresent = enclave.data?.key === "present";
  // "armed" means more than a key existing: the presence policy must be
  // enrolled, or approvals fall back to the in-app confirm dialog.
  const armed = keyPresent && enclave.data?.policy?.enrolled === true;
  const enforced = clients.data?.posture === "enforced";
  const killState = status?.kill.state;
  const engaged = killState === "engaged";

  return (
    <ViewShell
      title={t("nav.security")}
      sub={t("security.sub")}
      scroll={false}
      right={
        enclave.data === undefined ? (
          <Pill>{t("common.loading")}</Pill>
        ) : armed ? (
          <Pill tone="live">
            <TouchIdIcon />
            {t("security.pill_armed")}
          </Pill>
        ) : keyPresent ? (
          <Pill>{t("overview.map_host_key_only")}</Pill>
        ) : (
          <Pill>{t("security.pill_unarmed")}</Pill>
        )
      }
    >
      <div className="scroll">
        {enclave.error !== undefined && <ErrorNote>{enclave.error}</ErrorNote>}
        {clients.error !== undefined && <ErrorNote>{clients.error}</ErrorNote>}

        <section className="zone" aria-label={t("security.admission_title")}>
          <div className="zone-head">
            <SpecLabel as="h2">{t("security.admission_title")}</SpecLabel>
            <span className="zone-note">{t("security.admission_note")}</span>
          </div>
          <div className="policy-flow">
            {clients.data === undefined ? (
              <p className="m-0 py-2 text-xs text-text-3">{t("common.loading")}</p>
            ) : (
              <div className={`policy-row${enforced ? "" : " off"}`}>
                <div className="policy-info">
                  <div className="policy-name">{t("security.admission_name")}</div>
                  <Consequence>
                    {enforced ? (
                      t("security.admission_on")
                    ) : (
                      <>
                        {t("security.admission_off_1")}{" "}
                        <strong>{t("security.admission_off_2")}</strong>
                      </>
                    )}
                  </Consequence>
                </div>
                <div className="policy-side">
                  <span className={`policy-state${enforced ? " granted" : ""}`}>
                    {enforced ? t("security.state_enforced") : t("security.state_open")}
                  </span>
                  <Button variant="ghost" size="sm" onClick={() => setView("clients")}>
                    {t("security.open_clients")}
                  </Button>
                </div>
              </div>
            )}
          </div>
        </section>

        <section className="zone" aria-label={t("security.presence_title")}>
          <div className="zone-head">
            <SpecLabel as="h2">{t("security.presence_title")}</SpecLabel>
            <span className="zone-note">{t("security.presence_note")}</span>
          </div>
          <div className="policy-flow">
            <div className="policy-row">
              <div className="policy-info">
                <div className="policy-name">
                  {t("security.presence_release_name")}
                  <TouchIdChip />
                </div>
                <Consequence>
                  {t("security.presence_release_body_1")}{" "}
                  <strong>{t("security.presence_release_body_2")}</strong>
                </Consequence>
              </div>
              <div className="policy-side">
                <span className="policy-state granted">{t("security.state_always")}</span>
              </div>
            </div>
            <div className="policy-row">
              <div className="policy-info">
                <div className="policy-name">
                  {t("security.presence_trust_name")}
                  <TouchIdChip />
                </div>
                <Consequence>
                  {t("security.presence_trust_body_1")}{" "}
                  <strong>{t("security.presence_trust_body_2")}</strong>
                </Consequence>
              </div>
              <div className="policy-side">
                <span className="policy-state granted">{t("security.state_always")}</span>
              </div>
            </div>
            <div className="policy-row">
              <div className="policy-info">
                <div className="policy-name">
                  {t("security.presence_pair_name")}
                  <TouchIdChip />
                </div>
                <Consequence>{t("security.presence_pair_body")}</Consequence>
              </div>
              <div className="policy-side">
                <span className="policy-state granted">{t("security.state_always")}</span>
              </div>
            </div>
          </div>
        </section>

        <section className="zone" aria-label={t("security.grants_title")}>
          <div className="zone-head">
            <SpecLabel as="h2">{t("security.grants_title")}</SpecLabel>
          </div>
          <Consequence className="quiet">{t("security.managed_in_extension")}</Consequence>
        </section>

        <section className="zone" aria-label={t("security.confirm_title")}>
          <div className="zone-head">
            <SpecLabel as="h2">{t("security.confirm_title")}</SpecLabel>
          </div>
          <Consequence className="quiet">{t("security.managed_in_extension")}</Consequence>
        </section>
      </div>

      <div className="kill-note" role="note">
        <Dot tone={killState === undefined || killState === "off" ? "idle" : "down"} />
        <span>
          {killState === undefined
            ? t("common.loading")
            : engaged
              ? t("security.kill_note_engaged")
              : killState === "off"
                ? t("security.kill_note_off")
                : t("overview.kill_unreadable_state")}{" "}
          <strong className="font-semibold text-text-1">{t("security.kill_note_release")}</strong>
        </span>
        <Button variant="ghost" onClick={() => setView("overview")}>
          {t("security.open_overview")}
        </Button>
      </div>
    </ViewShell>
  );
}
