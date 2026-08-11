import { useEffect, useMemo, useState } from "react";
import {
  Consequence,
  ErrorNote,
  Mono,
  Pill,
  SpecLabel,
  TextInput,
  TouchIdChip,
} from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useAsync } from "@/hooks/useAsync";
import { useEpochEvent } from "@/hooks/useEpochEvent";
import { useI18n } from "@/hooks/useI18n";
import { POLICY_EPOCH_EVENT } from "@/lib/epoch-events";
import type { MessageKey } from "@/lib/i18n";
import { importSignWarning } from "@/lib/import-review";
import {
  changedFields,
  type DraftError,
  diffOverlay,
  draftErrors,
  draftFromValues,
  POLICY_FIELDS,
  type PolicyDraft,
  type PolicyFieldName,
  type PolicyFieldSpec,
  type PolicyGroup,
  valuesFromDraft,
} from "@/lib/policy-edit";
import {
  api,
  errorText,
  type PolicyOutcome,
  type PolicyOverlay,
  type PolicyValues,
} from "@/lib/tauri";

// The ADR-0032 policy editor (decision 5's app surface). The webview only
// drafts and displays: validity, direction (tighten vs relax), and both
// write lanes are decided in Rust. Apply lanes:
//  - a diff that relaxes nothing applies instantly through the in-process
//    free lane (policy_restrict; restrictions carry no attestation);
//  - anything relaxing - and, with no baseline yet, ANY change, since the
//    first write signs revision 1 - goes through the app's explicit confirm
//    dialog FIRST (validate-before-prompt), then ONE signed `policy set`
//    subprocess naming ALL changed fields. One atomic write and one Touch ID
//    sheet, so a refused tap never leaves a half-applied mixed edit
//    (restrict-then-set would strand the tightenings the user approved as a
//    package with the relaxations).
type Translate = (key: MessageKey, subs?: readonly string[]) => string;

const GROUPS: readonly { group: PolicyGroup; labelKey: MessageKey }[] = [
  { group: "grants", labelKey: "security.group_grants" },
  { group: "confirmations", labelKey: "security.group_confirmations" },
  { group: "timing", labelKey: "security.group_timing" },
  { group: "tools", labelKey: "security.group_tools" },
];

function fieldLabel(t: Translate, name: PolicyFieldName): string {
  const spec = POLICY_FIELDS.find((s) => s.name === name);
  return spec === undefined ? name : t(spec.labelKey);
}

export function PolicyEditor() {
  const { t } = useI18n();
  const status = useAsync(api.policyStatus);
  const history = useAsync(api.policyHistory);
  const defaults = useAsync(api.policyDefaults);
  // Read for the first-baseline dialog only: signing revision 1 writes the
  // consumed tombstone, which permanently closes the one-time import window
  // (none) or discards a recorded bag unseen (present) - the dialog says
  // which, one informing sentence, no extra friction.
  const pendingImport = useAsync(api.pendingImport);

  const store = status.data?.store;
  // What the bridge currently enforces, per the report: the effective
  // policy when a baseline exists, the core's deny defaults before one does
  // (never hardcoded here). Undefined while loading or on a store error.
  const anchor: PolicyValues | undefined =
    store === "present" ? status.data?.effective : store === "none" ? defaults.data : undefined;

  const [draft, setDraft] = useState<PolicyDraft>();
  const [busy, setBusy] = useState<string>();
  const [actionError, setActionError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const [outcome, setOutcome] = useState<PolicyOutcome>();
  const [pendingRelax, setPendingRelax] = useState<{
    overlay: PolicyOverlay;
    relaxes: string[];
    tightens: string[];
  }>();
  const [pendingRollback, setPendingRollback] = useState<number>();

  // The draft re-seeds from every fresh report (initial load and after each
  // apply); the editor deliberately does not reload on window focus, so
  // in-progress edits are never clobbered from the outside.
  useEffect(() => {
    setDraft(anchor === undefined ? undefined : draftFromValues(anchor));
  }, [anchor]);

  // A policy-epoch notice means a write actually landed (this app, the CLI,
  // a rollback): re-read so the editor drafts against what is now enforced.
  // Unlike a focus refresh, this clobbers an in-progress draft on purpose -
  // finishing an edit against a superseded anchor would misstate what the
  // apply dialog is about to show.
  useEpochEvent(POLICY_EPOCH_EVENT, () => {
    status.reload();
    history.reload();
    // A policy-epoch notice also fires when the host records a legacy
    // receipt, and revision 1 consumes it - either way the dialog's warning
    // must speak to the CURRENT import state.
    pendingImport.reload();
  });

  const clearResults = () => {
    setActionError(undefined);
    setNotice(undefined);
    setOutcome(undefined);
  };

  // Validity tracks the draft live (validate-before-prompt): the errors
  // render as the user types, and while any exist the overlay stays
  // undefined, so Apply is disabled and no plan call or dialog can start.
  const validation = useMemo<DraftError[]>(
    () => (draft === undefined ? [] : draftErrors(draft)),
    [draft],
  );
  const overlay =
    draft !== undefined && anchor !== undefined && validation.length === 0
      ? diffOverlay(valuesFromDraft(draft), anchor)
      : undefined;
  const dirty = overlay !== undefined && changedFields(overlay).length > 0;

  // Row identity for the history ring: append-only and never reordered, so
  // the position disambiguates entries that share a revision and timestamp
  // (repeated restrictions under one baseline). A revision appearing more
  // than once is flagged: rolling back to it may be refused as ambiguous
  // when the duplicates differ (identical duplicates roll back fine, so the
  // button stays enabled and the core's verbatim refusal renders otherwise).
  const historyEntries = history.data?.entries ?? [];
  const historyRows = historyEntries.map((entry, position) => ({
    entry,
    key: `${entry.revision ?? "unreadable"}-${entry.superseded_unix}-${position}`,
    duplicated:
      entry.revision !== null &&
      historyEntries.filter((e) => e.revision === entry.revision).length > 1,
  }));

  const apply = async () => {
    // The reactive validation already gates this path: while errors exist
    // the overlay is undefined and the button disabled (the Rust side
    // re-checks everything regardless).
    if (overlay === undefined || changedFields(overlay).length === 0) return;
    clearResults();
    setBusy("plan");
    try {
      const plan = await api.policyPlan(overlay);
      if (store === "present" && plan.relaxes.length === 0) {
        setBusy("restrict");
        await api.policyRestrict(overlay);
        setNotice(t("security.applied_restrict"));
        status.reload();
        history.reload();
      } else {
        setPendingRelax({ overlay, relaxes: plan.relaxes, tightens: plan.tightens });
      }
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setBusy(undefined);
    }
  };

  // Signed lane: invoked ONLY from the relax dialog's confirm handler (the
  // Touch ID sheet the subprocess raises must follow the app's own dialog).
  const confirmSet = async () => {
    if (pendingRelax === undefined) return;
    setBusy("set");
    try {
      const result = await api.policySet(pendingRelax.overlay);
      setOutcome(result);
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setPendingRelax(undefined);
      setBusy(undefined);
      status.reload();
      history.reload();
    }
  };

  // Rollback may relax, so it carries the same dialog-first obligation.
  const confirmRollback = async () => {
    if (pendingRollback === undefined) return;
    setBusy("rollback");
    try {
      const result = await api.policyRollback(pendingRollback);
      setOutcome(result);
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setPendingRollback(undefined);
      setBusy(undefined);
      status.reload();
      history.reload();
    }
  };

  const setBool = (name: PolicyFieldName, value: boolean) => {
    setDraft((d) => (d === undefined ? d : { ...d, [name]: value }));
  };
  const setText = (name: PolicyFieldName, value: string) => {
    setDraft((d) => (d === undefined ? d : { ...d, [name]: value }));
  };

  const fieldEdited = (spec: PolicyFieldSpec): boolean => {
    if (draft === undefined || anchor === undefined) return false;
    const seeded = draftFromValues(anchor);
    return draft[spec.name] !== seeded[spec.name];
  };

  const validationText = (error: DraftError): string => {
    const label = fieldLabel(t, error.field);
    if (error.kind === "ms") return t("security.invalid_ms", [label]);
    if (error.kind === "tool_count") return t("security.invalid_tools_count");
    return t("security.invalid_tool_name");
  };

  const renderRow = (spec: PolicyFieldSpec) => {
    if (draft === undefined) return null;
    const edited = fieldEdited(spec);
    if (spec.kind === "bool") {
      const value = draft[spec.name] as boolean;
      return (
        <div className="policy-row" key={spec.name}>
          <div className="policy-info">
            <div className="policy-name">
              {t(spec.labelKey)}
              {edited && <Pill tone="pending">{t("security.edited")}</Pill>}
            </div>
          </div>
          <div className="policy-side">
            <span className={`policy-state${value ? " granted" : ""}`}>
              {value ? t("security.on") : t("security.off")}
            </span>
            <Button
              variant="ghost"
              size="sm"
              disabled={busy !== undefined}
              onClick={() => setBool(spec.name, !value)}
            >
              {value ? t("security.turn_off") : t("security.turn_on")}
            </Button>
          </div>
        </div>
      );
    }
    const text = draft[spec.name] as string;
    return (
      <div className="policy-row" key={spec.name}>
        <div className="policy-info">
          <div className="policy-name">
            {t(spec.labelKey)}
            {edited && <Pill tone="pending">{t("security.edited")}</Pill>}
          </div>
          {spec.kind === "tools" && <Consequence>{t("security.tools_hint")}</Consequence>}
        </div>
        <div className="policy-side">
          <TextInput
            aria-label={t(spec.labelKey)}
            inputMode={spec.kind === "ms" ? "numeric" : "text"}
            className={spec.kind === "ms" ? "w-28 text-right" : "w-64"}
            value={text}
            disabled={busy !== undefined}
            placeholder={spec.kind === "tools" ? t("security.tools_placeholder") : undefined}
            onChange={(e) => setText(spec.name, e.target.value)}
          />
        </div>
      </div>
    );
  };

  return (
    <>
      <section className="zone" aria-label={t("security.managed_title")}>
        <div className="zone-head">
          <SpecLabel as="h2">{t("security.managed_title")}</SpecLabel>
          <span className="zone-note">{t("security.policy_note")}</span>
        </div>

        {status.error !== undefined && <ErrorNote>{status.error}</ErrorNote>}
        {store === "error" && (
          <ErrorNote>
            {t("security.policy_error", [
              status.data?.detail ?? t("security.policy_error_unknown"),
            ])}
          </ErrorNote>
        )}

        {store === "present" && (
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Pill>{t("security.policy_revision", [String(status.data?.revision ?? 0)])}</Pill>
            <Pill tone={status.data?.signed === true ? "live" : "pending"}>
              {status.data?.signed === true
                ? t("security.policy_signed")
                : t("security.policy_unsigned")}
            </Pill>
            {status.data?.overlay_active === true && (
              <Pill tone="pending">{t("security.policy_overlay")}</Pill>
            )}
          </div>
        )}
        {store === "none" && (
          <Consequence className="quiet">{t("security.policy_none")}</Consequence>
        )}

        {status.data === undefined && status.error === undefined && (
          <p className="m-0 py-2 text-xs text-text-3">{t("common.loading")}</p>
        )}

        {draft !== undefined && (
          <>
            {GROUPS.map(({ group, labelKey }) => (
              <div className="policy-flow" key={group}>
                <SpecLabel className="mt-3 block">{t(labelKey)}</SpecLabel>
                {POLICY_FIELDS.filter((spec) => spec.group === group).map(renderRow)}
              </div>
            ))}

            {validation.map((error) => (
              <ErrorNote key={`${error.field}-${error.kind}`}>{validationText(error)}</ErrorNote>
            ))}
            {actionError !== undefined && <ErrorNote>{actionError}</ErrorNote>}
            {outcome !== undefined &&
              (outcome.ok ? (
                outcome.transcript !== "" && <Mono>{outcome.transcript}</Mono>
              ) : (
                <ErrorNote>{outcome.transcript}</ErrorNote>
              ))}
            {notice !== undefined && <Consequence>{notice}</Consequence>}

            <div className="mt-3 flex items-center gap-2">
              <Button
                variant="primary"
                disabled={busy !== undefined || !dirty}
                onClick={() => void apply()}
              >
                {busy !== undefined ? t("common.working") : t("security.apply")}
              </Button>
              <Button
                variant="ghost"
                disabled={busy !== undefined || draft === undefined || anchor === undefined}
                onClick={() => {
                  if (anchor !== undefined) setDraft(draftFromValues(anchor));
                  clearResults();
                }}
              >
                {t("security.revert")}
              </Button>
              <TouchIdChip />
              <span className="text-[11px] text-text-3">{t("security.apply_note")}</span>
            </div>
          </>
        )}
      </section>

      <section className="zone" aria-label={t("security.history_title")}>
        <div className="zone-head">
          <SpecLabel as="h2">{t("security.history_title")}</SpecLabel>
          <span className="zone-note">{t("security.history_note")}</span>
        </div>
        {history.error !== undefined && <ErrorNote>{history.error}</ErrorNote>}
        {history.data !== undefined && history.data.entries.length === 0 && (
          <Consequence className="quiet">{t("security.history_empty")}</Consequence>
        )}
        {history.data !== undefined && history.data.entries.length > 0 && (
          <div className="policy-flow">
            {historyRows.map(({ entry, key, duplicated }) => (
              <div className="policy-row" key={key}>
                <div className="policy-info">
                  <div className="policy-name">
                    {entry.revision === null
                      ? t("security.history_unreadable")
                      : t("security.policy_revision", [String(entry.revision)])}
                    <Pill tone={entry.signed ? "live" : "pending"}>
                      {entry.signed ? t("security.policy_signed") : t("security.policy_unsigned")}
                    </Pill>
                    {entry.overlay_active && (
                      <Pill tone="pending">{t("security.policy_overlay")}</Pill>
                    )}
                  </div>
                  <Consequence>
                    {t("security.history_superseded", [
                      new Date(entry.superseded_unix * 1000).toLocaleString(),
                    ])}
                  </Consequence>
                  {duplicated && (
                    <Consequence className="quiet">{t("security.history_duplicate")}</Consequence>
                  )}
                </div>
                <div className="policy-side">
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={busy !== undefined || entry.revision === null}
                    onClick={() => {
                      clearResults();
                      if (entry.revision !== null) setPendingRollback(entry.revision);
                    }}
                  >
                    {t("security.rollback")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <ConfirmDialog
        open={pendingRelax !== undefined}
        onOpenChange={(open) => !open && setPendingRelax(undefined)}
        title={
          store === "none" ? t("security.first_dialog_title") : t("security.relax_dialog_title")
        }
        body={
          <>
            {pendingRelax !== undefined && pendingRelax.relaxes.length > 0 && (
              <>
                <p className="m-0">{t("security.relax_dialog_fields")}</p>
                <ul className="my-1 pl-4">
                  {pendingRelax.relaxes.map((name) => (
                    <li key={name}>{fieldLabel(t, name as PolicyFieldName)}</li>
                  ))}
                </ul>
              </>
            )}
            {pendingRelax !== undefined && pendingRelax.tightens.length > 0 && (
              <>
                <p className="m-0">{t("security.relax_dialog_also_tightens")}</p>
                <ul className="my-1 pl-4">
                  {pendingRelax.tightens.map((name) => (
                    <li key={name}>{fieldLabel(t, name as PolicyFieldName)}</li>
                  ))}
                </ul>
              </>
            )}
            <p className="m-0">
              {store === "none" ? t("security.first_dialog_body") : t("security.relax_dialog_body")}
            </p>
            {store === "none" &&
              (() => {
                const warning = importSignWarning(pendingImport.data?.state, pendingImport.error);
                if (warning === undefined) return null;
                return (
                  <p className="m-0">
                    {warning.kind === "closes_window" && t("security.first_dialog_import_warning")}
                    {warning.kind === "discards_pending" &&
                      t("security.first_dialog_import_discard_warning")}
                    {warning.kind === "probe_failed" &&
                      t("security.first_dialog_import_probe_error", [warning.detail])}
                  </p>
                );
              })()}
          </>
        }
        confirmLabel={t("security.relax_confirm")}
        busy={busy === "set"}
        onConfirm={() => void confirmSet()}
      />

      <ConfirmDialog
        open={pendingRollback !== undefined}
        onOpenChange={(open) => !open && setPendingRollback(undefined)}
        title={t("security.rollback_dialog_title", [String(pendingRollback ?? "")])}
        body={t("security.rollback_dialog_body")}
        confirmLabel={t("security.rollback_confirm")}
        busy={busy === "rollback"}
        onConfirm={() => void confirmRollback()}
      />
    </>
  );
}
