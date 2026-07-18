import { useEffect } from "react";
import {
  ChipMono,
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
import { isArmed } from "@/lib/armed";
import { api } from "@/lib/tauri";
import { useAppStore } from "@/store";

// The Security screen shows policy as it is enforced TODAY. Client
// admission and the presence gates are host-side facts; capability grants
// and per-tool confirmation policy still live in the extension (they move
// host-side in a later protocol phase), so that section carries a quiet
// pointer instead of dead controls - a toggle that does nothing is a lie.
export function SecurityView() {
  const { t } = useI18n();
  const status = useAppStore((s) => s.status);
  const statusFresh = useAppStore((s) => s.statusFresh);
  const setView = useAppStore((s) => s.setView);
  const enclave = useAsync(api.enclaveStatus);
  const clients = useAsync(api.clientsList);

  // status refreshes on focus (App.tsx); the enclave/clients reads behind
  // the armed claim and the admission row must not lag it
  useEffect(() => {
    const onFocus = () => {
      enclave.reload();
      clients.reload();
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [enclave.reload, clients.reload]);

  const keyPresent = enclave.data?.key === "present";
  // the ONE armed/attested predicate, shared with OverviewView: key present,
  // presence policy enrolled, and reads that actually succeeded
  const armed = isArmed(enclave, statusFresh);
  const enforced = clients.data?.posture === "enforced";
  const killState = status?.kill.state;
  const engaged = killState === "engaged";

  // Without enclave hardware enrolled, the presence proof degrades to the
  // in-app confirm dialog (Floor::AppConfirm): the chip must say which
  // mechanism actually answers, not overstate the hardware.
  const presenceChip = armed ? <TouchIdChip /> : <ChipMono>{t("auth.app_confirm")}</ChipMono>;

  return (
    <ViewShell
      title={t("nav.security")}
      sub={t("security.sub")}
      scroll={false}
      right={
        enclave.data === undefined ? (
          <Pill>{t("common.loading")}</Pill>
        ) : armed ? (
          // a stored policy label, not a live signal: neutral ink
          <Pill>
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
      {/* biome-ignore lint/a11y/noNoninteractiveTabindex: the scroll pane must be keyboard-reachable (WKWebView does not focus scrollers itself) */}
      {/* biome-ignore lint/a11y/useSemanticElements: role=region names the focusable scroll pane */}
      <div className="scroll" tabIndex={0} role="region" aria-label={t("nav.security")}>
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
                  {presenceChip}
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
                  {presenceChip}
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
                  {presenceChip}
                </div>
                <Consequence>{t("security.presence_pair_body")}</Consequence>
              </div>
              <div className="policy-side">
                <span className="policy-state granted">{t("security.state_always")}</span>
              </div>
            </div>
          </div>
        </section>

        {/* grants and per-tool confirmation policy are one honest pointer,
            not two headed sections with the same body */}
        <section className="zone" aria-label={t("security.managed_title")}>
          <div className="zone-head">
            <SpecLabel as="h2">{t("security.managed_title")}</SpecLabel>
          </div>
          <Consequence className="quiet">{t("security.managed_in_extension")}</Consequence>
        </section>
      </div>

      <div className="kill-note" role="note">
        <Dot
          tone={
            killState === undefined ? "idle" : killState === "off" && statusFresh ? "idle" : "down"
          }
        />
        <span>
          {killState === undefined
            ? t("common.loading")
            : engaged
              ? t("security.kill_note_engaged")
              : killState === "off" && statusFresh
                ? t("security.kill_note_off")
                : // unreadable, or a snapshot the latest refresh failed to
                  // renew: claim nothing (fail closed)
                  t("overview.kill_unreadable_state")}{" "}
          <strong className="font-semibold text-text-1">{t("security.kill_note_release")}</strong>
        </span>
        <Button variant="ghost" onClick={() => setView("overview")}>
          {t("security.open_overview")}
        </Button>
      </div>
    </ViewShell>
  );
}
