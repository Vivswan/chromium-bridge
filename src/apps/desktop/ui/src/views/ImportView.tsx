import { useEffect, useState } from "react";
import { Consequence, ErrorNote, Mono, Pill, SpecLabel, ViewShell } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useAsync } from "@/hooks/useAsync";
import { useEpochEvent } from "@/hooks/useEpochEvent";
import { useI18n } from "@/hooks/useI18n";
import { POLICY_EPOCH_EVENT } from "@/lib/epoch-events";
import type { MessageKey } from "@/lib/i18n";
import { adoptLane, type ImportRow, importRows } from "@/lib/import-review";
import { POLICY_FIELDS } from "@/lib/policy-edit";
import { api, errorText, type PolicyOutcome } from "@/lib/tauri";
import { useAppStore } from "@/store";

// The first-run legacy import screen (ADR-0032 decision 8). The recorded
// bag is a SUGGESTION, never policy: this screen shows what it would map to
// against the deny defaults, and the only way anything applies is the same
// signed grant lane every policy write takes (`policy_set` - one Touch ID on
// an enrolled Mac, the app's documented unsigned floor on a genuinely
// unenrolled one). Adopting is what consumes the pending import (revision
// 1's locked write); Skip leaves the offer standing until a first baseline
// signs anywhere.

type Translate = (key: MessageKey, subs?: readonly string[]) => string;

function valueText(t: Translate, value: boolean | number | string[]): string {
  if (typeof value === "boolean") return value ? t("security.on") : t("security.off");
  if (Array.isArray(value)) return value.length === 0 ? t("import.tools_none") : value.join(", ");
  return String(value);
}

export function ImportView() {
  const { t } = useI18n();
  const setView = useAppStore((s) => s.setView);
  const setImportAttention = useAppStore((s) => s.setImportAttention);
  const survey = useAsync(api.pendingImport);
  const defaults = useAsync(api.policyDefaults);
  const enclave = useAsync(api.enclaveStatus);
  const [pendingAdopt, setPendingAdopt] = useState<{ relaxes: string[] }>();
  const [busy, setBusy] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [outcome, setOutcome] = useState<PolicyOutcome>();

  // The sidebar entry tracks the real state: attention while a bag awaits
  // review (or the store is unreadable - the user should see the notice),
  // gone once consumed or absent.
  const state = survey.data?.state;
  useEffect(() => {
    if (state !== undefined) setImportAttention(state === "present" || state === "error");
  }, [state, setImportAttention]);

  // A policy write landed somewhere (this app's editor, the CLI): revision 1
  // consumes the pending import, so re-read rather than keep a stale offer.
  useEpochEvent(POLICY_EPOCH_EVENT, () => {
    survey.reload();
  });

  const suggestion = survey.data?.state === "present" ? survey.data.suggestion : undefined;
  const rows: ImportRow[] =
    suggestion !== undefined && defaults.data !== undefined
      ? importRows(suggestion, defaults.data)
      : [];
  const lane = enclave.data === undefined ? undefined : adoptLane(enclave.data);

  const fieldLabel = (wireName: string): string => {
    const spec = POLICY_FIELDS.find((s) => s.name === wireName);
    return spec === undefined ? wireName : t(spec.labelKey);
  };

  // Validate-before-prompt: the relax classification (Rust's direction
  // table) is fetched first, so the dialog names exactly which fields grant
  // more than the deny baseline before any signature can be asked for.
  const beginAdopt = async () => {
    if (suggestion === undefined) return;
    setActionError(undefined);
    setOutcome(undefined);
    setBusy("plan");
    try {
      const plan = await api.policyPlan(suggestion.overlay);
      setPendingAdopt({ relaxes: plan.relaxes });
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setBusy(undefined);
    }
  };

  // The grant lane: invoked ONLY from the adopt dialog's confirm handler
  // (the dialog is what the app-confirm floor asserts, and the Touch ID
  // sheet on the enrolled lane must follow the app's own dialog). policyAdopt
  // is policySet behind a first-baseline gate: the reviewed values can only
  // ever become revision 1.
  const confirmAdopt = async () => {
    if (suggestion === undefined) return;
    setBusy("adopt");
    try {
      const result = await api.policyAdopt(suggestion.overlay);
      setOutcome(result);
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setPendingAdopt(undefined);
      setBusy(undefined);
      survey.reload();
    }
  };

  return (
    <ViewShell title={t("nav.import")} sub={t("import.sub")}>
      {survey.error !== undefined && <ErrorNote>{survey.error}</ErrorNote>}
      {survey.data === undefined && survey.error === undefined && (
        <p className="m-0 py-2 text-xs text-text-3">{t("common.loading")}</p>
      )}

      {state === "none" && <Consequence className="quiet">{t("import.none_body")}</Consequence>}
      {state === "consumed" && (
        <>
          <Consequence className="quiet">{t("import.consumed_body")}</Consequence>
          <div className="mt-2">
            <Button size="sm" onClick={() => setView("security")}>
              {t("nav.security")}
            </Button>
          </div>
        </>
      )}
      {survey.data?.state === "error" && (
        <ErrorNote>{t("import.error_body", [survey.data.detail])}</ErrorNote>
      )}

      {/* Rendered outside the suggestion block: a successful adopt reloads
          the survey into the consumed state (dropping the suggestion), and
          the write's outcome must survive that flip, not flicker away. */}
      {actionError !== undefined && <ErrorNote>{actionError}</ErrorNote>}
      {outcome !== undefined &&
        (outcome.ok ? (
          outcome.transcript !== "" && <Mono>{outcome.transcript}</Mono>
        ) : (
          <ErrorNote>{outcome.transcript}</ErrorNote>
        ))}

      {suggestion !== undefined && (
        <>
          <section className="zone" aria-label={t("import.review_title")}>
            <div className="zone-head">
              <SpecLabel as="h2">{t("import.review_title")}</SpecLabel>
              <span className="zone-note">{t("import.review_note")}</span>
            </div>
            {rows.length === 0 && defaults.data !== undefined && (
              <Consequence className="quiet">{t("import.empty_mapping")}</Consequence>
            )}
            {rows.length > 0 && (
              <div className="policy-flow">
                {rows.map((row) => (
                  <div className="policy-row" key={row.spec.name}>
                    <div className="policy-info">
                      <div className="policy-name">
                        {t(row.spec.labelKey)}
                        {row.changed && <Pill tone="pending">{t("import.changed")}</Pill>}
                      </div>
                      {row.changed && (
                        <Consequence>
                          {t("import.default_was", [valueText(t, row.fallback)])}
                        </Consequence>
                      )}
                    </div>
                    <div className="policy-side">
                      <span className={`policy-state${row.changed ? " granted" : ""}`}>
                        {valueText(t, row.suggested)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
            {suggestion.ignored.length > 0 && (
              <Consequence className="quiet mt-2">
                {t("import.ignored_note")}{" "}
                <span className="mono">{suggestion.ignored.join(", ")}</span>
              </Consequence>
            )}
          </section>

          {lane?.kind === "floor" && (
            <Consequence className="mt-2">{t("import.floor_banner")}</Consequence>
          )}
          {lane?.kind === "blocked" && <ErrorNote>{t("import.blocked", [lane.detail])}</ErrorNote>}
          {enclave.error !== undefined && (
            <ErrorNote>{t("import.blocked", [enclave.error])}</ErrorNote>
          )}

          <div className="mt-3 flex items-center gap-2">
            <Button
              variant="primary"
              disabled={
                busy !== undefined ||
                defaults.data === undefined ||
                lane === undefined ||
                lane.kind === "blocked"
              }
              onClick={() => void beginAdopt()}
            >
              {busy !== undefined ? t("common.working") : t("import.adopt")}
            </Button>
            <Button
              variant="ghost"
              disabled={busy !== undefined}
              onClick={() => setView("overview")}
            >
              {t("import.skip")}
            </Button>
            <span className="text-[11px] text-text-3">{t("import.skip_note")}</span>
          </div>
        </>
      )}

      <ConfirmDialog
        open={pendingAdopt !== undefined}
        onOpenChange={(open) => !open && setPendingAdopt(undefined)}
        title={t("import.adopt_dialog_title")}
        body={
          <>
            {pendingAdopt !== undefined && pendingAdopt.relaxes.length > 0 && (
              <>
                <p className="m-0">{t("import.adopt_relaxes")}</p>
                <ul className="my-1 pl-4">
                  {pendingAdopt.relaxes.map((name) => (
                    <li key={name}>{fieldLabel(name)}</li>
                  ))}
                </ul>
              </>
            )}
            <p className="m-0">
              {lane?.kind === "floor"
                ? t("import.adopt_dialog_body_floor")
                : t("import.adopt_dialog_body_signed")}
            </p>
          </>
        }
        confirmLabel={t("import.adopt_confirm")}
        busy={busy === "adopt"}
        onConfirm={() => void confirmAdopt()}
      />
    </ViewShell>
  );
}
