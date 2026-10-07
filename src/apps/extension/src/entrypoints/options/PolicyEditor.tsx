import type { PolicyHistoryRow } from "@chromium-bridge/shared/generated/envelope";
import { OP_NAMES } from "@chromium-bridge/shared/generated/ops";
import {
  BOOL_POLICY_FIELDS,
  type BoolPolicyField,
  MS_POLICY_FIELDS,
  type MsPolicyField,
  POLICY_DEFAULTS,
  POLICY_DIRECTIONS,
  type PolicyOverlay,
  type PolicyValues,
} from "@chromium-bridge/shared/generated/policy";
import { foldPolicyOverlay, relaxedPolicyFields } from "@chromium-bridge/shared/policy-compare";
import type { RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import { useCallback, useEffect, useId, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";
import { PresenceActStatus } from "./PresenceActStatus";
import { usePresenceAct } from "./usePresenceAct";

// The host-owned policy editor, both lanes. Direction is recomputed from the generated catalogue, never from a
// control's own idea of which way it points, and the host's seams decide again regardless.
//
//   tightening   restrict_policy, applied at once (the free lane `policy restrict` runs)
//   loosening    grant_policy behind this browser's tap (the grant lane `policy set` runs); the host refuses
//                before any prompt on a keyless host, in the CLI's words
//   history      the superseded-revision ring, each row with a roll-back that takes the lane its direction decides
//
// Before any policy is signed, the controls edit the deny baseline this browser enforces and every edit is a
// grant, whichever way it points: the first baseline is a signed write (`policy restrict` has nothing to
// restrict yet), so it can be signed from here as it can with `policy set`.
export function PolicyEditor() {
  const { t } = useI18n();
  const [view, setView] = useState<RuntimeResponse<"get_policy"> | null>(null);
  const [history, setHistory] = useState<RuntimeResponse<"get_policy_history"> | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setView(await send({ type: "get_policy" }));
  }, []);
  const refreshHistory = useCallback(async () => {
    setHistory(await send({ type: "get_policy_history" }));
  }, []);
  const presence = usePresenceAct(refreshHistory);

  useEffect(() => {
    void refresh();
    void refreshHistory();
    // The posture folds the policy record, the cutover flag, AND the pin (a revoke blocks it with the record
    // untouched), so any local change re-reads it rather than this page keeping the owner's key list. The ring
    // is re-read on the same signal and on demand: a write from another surface that leaves the enforced
    // values unchanged still pushes a ring entry but moves nothing in storage.
    const onChanged = (_changes: Record<string, unknown>, area: string) => {
      if (area === "local") {
        void refresh();
        void refreshHistory();
      }
    };
    browser.storage.onChanged.addListener(onChanged);
    return () => browser.storage.onChanged.removeListener(onChanged);
  }, [refresh, refreshHistory]);

  const restrict = async (overlay: PolicyOverlay) => {
    setBusy(true);
    setActionError(null);
    presence.cancel();
    const r = await send({ type: "restrict_policy", overlay });
    if (!r.ok) setActionError(t("policy.apply_failed", [r.error]));
    setBusy(false);
  };

  if (view === null) return <div className="py-2 text-xs text-text-3">{t("policy.loading")}</div>;
  if (!view.ok) {
    return (
      <div role="status" className="py-2 text-xs font-semibold text-pending">
        {t("policy.error", [view.error])}
      </div>
    );
  }
  if (view.posture.kind === "blocked") {
    return (
      <div className="py-1">
        <div className="flex items-center gap-2 text-[13px] font-semibold text-danger">
          <span className="status-dot down" />
          {t("policy.blocked_title")}
        </div>
        <p className="consequence mt-1">{view.posture.reason}</p>
      </div>
    );
  }

  const firstBaseline = view.posture.kind === "preCutover";
  const effective = view.posture.kind === "active" ? view.posture.effective : POLICY_DEFAULTS;
  const needsTap = (overlay: PolicyOverlay) => firstBaseline || wouldRelax(effective, overlay);
  const grant = (overlay: PolicyOverlay) => {
    setActionError(null);
    void presence.run(() => send({ type: "grant_policy", overlay }));
  };
  const edit = (overlay: PolicyOverlay) => {
    if (needsTap(overlay)) grant(overlay);
    else void restrict(overlay);
  };
  const pending = busy || presence.busy;
  return (
    <div className="py-1">
      {firstBaseline ? (
        <div className="mb-2">
          <div className="text-[13px] font-medium">{t("policy.none_title")}</div>
          <p className="consequence mt-1">{t("policy.none_desc")}</p>
        </div>
      ) : (
        <p className="consequence m-0">{t("policy.desc")}</p>
      )}
      <fieldset disabled={pending} className={FORM}>
        {BOOL_POLICY_FIELDS.map((field) => (
          <BoolRow key={field} field={field} {...{ effective, needsTap, onEdit: edit }} />
        ))}
        {MS_POLICY_FIELDS.map((field) => (
          <MsRow key={field} field={field} {...{ effective, needsTap, onEdit: edit }} />
        ))}
        <ToolsRow {...{ effective, pending, onEdit: edit }} />
      </fieldset>
      {!firstBaseline && <p className="consequence mt-2">{t("policy.effective_note")}</p>}
      <div
        role="alert"
        className={actionError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
      >
        {actionError}
      </div>
      <PresenceActStatus
        presence={presence}
        confirmLabel={t("policy.grant_confirm")}
        refused={(sentence) => t("policy.grant_failed", [sentence])}
      />
      <HistoryBlock
        history={history}
        pending={pending}
        onRefresh={() => void refreshHistory()}
        onRollback={(entry) => {
          setActionError(null);
          void presence.run(() =>
            send({
              type: "rollback_policy",
              revision: entry.revision,
              entry: { id: entry.id },
            }),
          );
        }}
      />
    </div>
  );
}

/** The disabled-fieldset wrapper's own box reset; `min-w-0` lifts the element's min-content floor. */
const FORM = "m-0 min-w-0 border-0 p-0";

interface RowProps {
  effective: PolicyValues;
  /** Whether `overlay` takes the grant lane: it relaxes a field, or no baseline exists yet. */
  needsTap: (overlay: PolicyOverlay) => boolean;
  onEdit: (overlay: PolicyOverlay) => void;
}

/** Whether applying `overlay` over the enforced values would relax any field: the host's own direction check
 * (policy::restricts_or_equal), run here so the page knows which lane a move takes before it asks. */
function wouldRelax(effective: PolicyValues, overlay: PolicyOverlay): boolean {
  return relaxedPolicyFields(foldPolicyOverlay(effective, overlay), effective).length > 0;
}

function BoolRow({ field, effective, needsTap, onEdit }: RowProps & { field: BoolPolicyField }) {
  const { t } = useI18n();
  const id = useId();
  const checked = effective[field];
  const flipRelaxes = needsTap({ [field]: !checked });
  return (
    <div className="flex items-start gap-3.5 border-b border-edge py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <label htmlFor={id} className="block cursor-pointer text-[13px] font-medium">
          {t(`confirm.pf_${field}`)}
        </label>
        {flipRelaxes && (
          <div className="mt-0.5 text-[11px] text-text-3">{t("policy.needs_presence")}</div>
        )}
      </div>
      <Switch
        id={id}
        checked={checked}
        onCheckedChange={(next) => onEdit({ [field]: next })}
        className="mt-0.5"
      />
    </div>
  );
}

/** The draft as a duration, or null while it is blank or not a non-negative safe integer: a blank input must
 * never read as 0, which for every window is a tightening the user did not type. */
function parseDuration(draft: string): number | null {
  if (draft.trim() === "") return null;
  const n = Number(draft);
  return Number.isSafeInteger(n) && n >= 0 ? n : null;
}

function MsRow({ field, effective, needsTap, onEdit }: RowProps & { field: MsPolicyField }) {
  const { t } = useI18n();
  const id = useId();
  const current = effective[field];
  const [draft, setDraft] = useState(String(current));
  useEffect(() => setDraft(String(current)), [current]);
  const candidate = parseDuration(draft);
  const changed = candidate !== null && candidate !== current;
  const relaxes = changed && needsTap({ [field]: candidate });
  return (
    <div className="flex items-start gap-3.5 border-b border-edge py-3 last:border-b-0">
      <div className="min-w-0 flex-1">
        <label htmlFor={id} className="block text-[13px] font-medium">
          {t(`confirm.pf_${field}`)}
        </label>
        <div className="mt-0.5 text-[11px] text-text-3">
          {POLICY_DIRECTIONS[field] === "growsPermissiveZeroTop"
            ? t("policy.zero_top_note")
            : t("policy.ms_note")}
        </div>
        {relaxes && (
          <div className="mt-0.5 text-[11px] text-text-3">{t("policy.needs_presence")}</div>
        )}
      </div>
      <div className="flex items-center gap-2">
        <input
          id={id}
          type="number"
          min={0}
          step={1000}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          className="tnum w-28 rounded-md border border-edge-strong bg-surface-1 px-2 py-1 text-right font-mono text-xs text-text-1"
        />
        <span className="text-[11px] text-text-3">{t("policy.ms_unit")}</span>
        <Button
          onClick={() => {
            if (candidate !== null) onEdit({ [field]: candidate });
          }}
          disabled={!changed}
        >
          {t("policy.apply")}
        </Button>
      </div>
    </div>
  );
}

function ToolsRow({
  effective,
  pending,
  onEdit,
}: Omit<RowProps, "needsTap"> & { pending: boolean }) {
  const { t } = useI18n();
  const disabled = effective.disabledTools;
  const candidates = OP_NAMES.filter((op) => !disabled.includes(op));
  const [pick, setPick] = useState<string>("");
  return (
    <div className="border-b border-edge py-3 last:border-b-0">
      <div className="text-[13px] font-medium">{t("confirm.pf_disabledTools")}</div>
      {/* The overlay states the WHOLE disabled set, as `--disabled-tools` does; re-enabling one is a relaxation. */}
      <div className="mt-1 flex flex-wrap items-center gap-1.5">
        {disabled.length === 0 && (
          <span className="text-[11px] text-text-3">{t("policy.tools_none")}</span>
        )}
        {disabled.map((tool) => (
          <span key={tool} className="chip-mono inline-flex items-center gap-1">
            {tool}
            <button
              type="button"
              aria-label={t("policy.enable_tool", [tool])}
              title={t("policy.needs_presence")}
              className="cursor-pointer text-text-3 hover:text-text-1 disabled:cursor-default"
              onClick={() => onEdit({ disabledTools: disabled.filter((d) => d !== tool) })}
            >
              x
            </button>
          </span>
        ))}
      </div>
      <div className="mt-2 flex items-center gap-2">
        {/* The Radix select reads its own prop, not the disabled fieldset around it. */}
        <Select value={pick} onValueChange={setPick} disabled={pending}>
          <SelectTrigger className="min-w-48" aria-label={t("policy.pick_tool")}>
            <SelectValue placeholder={t("policy.pick_tool")} />
          </SelectTrigger>
          <SelectContent>
            {candidates.map((op) => (
              <SelectItem key={op} value={op}>
                {op}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Button
          onClick={() => {
            onEdit({ disabledTools: [...disabled, pick] });
            setPick("");
          }}
          disabled={pick === "" || disabled.includes(pick)}
        >
          {t("policy.disable_tool")}
        </Button>
      </div>
    </div>
  );
}

function HistoryBlock({
  history,
  pending,
  onRefresh,
  onRollback,
}: {
  history: RuntimeResponse<"get_policy_history"> | null;
  pending: boolean;
  onRefresh: () => void;
  onRollback: (entry: RollbackEntry) => void;
}) {
  const { t } = useI18n();
  return (
    <fieldset disabled={pending} className={`${FORM} mt-4`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[13px] font-medium">{t("policy.history_title")}</div>
          <p className="consequence mt-1">{t("policy.history_desc")}</p>
        </div>
        <Button variant="ghost" onClick={onRefresh}>
          {t("policy.history_refresh")}
        </Button>
      </div>
      {history === null && <div className="mt-2 text-xs text-text-3">{t("policy.loading")}</div>}
      {history && !history.ok && (
        <div role="status" className="mt-2 text-xs font-semibold text-pending">
          {t("policy.history_error", [history.error])}
        </div>
      )}
      {history?.ok && history.entries.length === 0 && (
        <div className="mt-2 text-xs text-text-3">{t("policy.history_empty")}</div>
      )}
      {history?.ok && history.entries.length > 0 && (
        <ul className="m-0 mt-1 list-none p-0">
          {historyEntries(history.entries).map((entry) => (
            <HistoryRowItem key={entry.key} entry={entry} onRollback={onRollback} />
          ))}
        </ul>
      )}
    </fieldset>
  );
}

/** One ring entry as the page renders it, decided once where the wire row enters: a readable revision with its
 * roll-back, or a damaged entry that offers none. The roll-back names the record's content identity, since a
 * revision alone can be ambiguous (policy/plan.rs find_history_effective says when). Two identical records (one
 * restriction repeated within a second) share an id and a state, so the row key adds the occurrence. */
type HistoryEntry = { id: string; key: string; supersededAt: string } & (
  | { kind: "revision"; revision: number; signed: boolean; overlayActive: boolean }
  | { kind: "damaged" }
);

/** The row a roll-back names: the revision for the plan, the record's identity for the row. */
type RollbackEntry = Extract<HistoryEntry, { kind: "revision" }>;

function historyEntries(rows: PolicyHistoryRow[]): HistoryEntry[] {
  const seen = new Map<string, number>();
  return rows.map((row) => {
    const nth = seen.get(row.id) ?? 0;
    seen.set(row.id, nth + 1);
    const shared = {
      id: row.id,
      key: `${row.id}-${nth}`,
      supersededAt: new Date(row.superseded_unix * 1000).toLocaleString(),
    };
    return row.revision === undefined
      ? { ...shared, kind: "damaged" }
      : {
          ...shared,
          kind: "revision",
          revision: row.revision,
          signed: row.signed,
          overlayActive: row.overlay_active,
        };
  });
}

function HistoryRowItem({
  entry,
  onRollback,
}: {
  entry: HistoryEntry;
  onRollback: (entry: RollbackEntry) => void;
}) {
  const { t } = useI18n();
  if (entry.kind === "damaged") {
    return (
      <li className="flex items-center gap-3 border-b border-edge py-2 last:border-b-0">
        <div className="min-w-0 flex-1 text-xs font-medium text-text-1">
          {t("policy.history_damaged", [entry.supersededAt])}
        </div>
      </li>
    );
  }
  return (
    <li className="flex items-center gap-3 border-b border-edge py-2 last:border-b-0">
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium text-text-1">
          {t("policy.history_row", [String(entry.revision), entry.supersededAt])}
        </div>
        <div className="font-mono text-[11px] text-text-3">
          {entry.signed ? t("policy.history_signed") : t("policy.history_unsigned")}
          {entry.overlayActive && `, ${t("policy.history_overlay")}`}
        </div>
      </div>
      <Button variant="ghost" onClick={() => onRollback(entry)}>
        {t("policy.rollback")}
      </Button>
    </li>
  );
}
