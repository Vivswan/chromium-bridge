import { OP_NAMES } from "@chromium-bridge/shared/ops.gen";
import {
  BOOL_POLICY_FIELDS,
  type BoolPolicyField,
  MS_POLICY_FIELDS,
  type MsPolicyField,
  POLICY_DIRECTIONS,
  type PolicyOverlay,
  type PolicyValues,
} from "@chromium-bridge/shared/policy.gen";
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

// The host-owned policy editor, restriction lane only: relaxing moves are disabled because the signed grant
// lane needs a presence tap this page cannot give yet. Direction is recomputed from the generated catalogue,
// never from a control's own idea of which way it points, and the host's seam refuses a relaxation regardless.
export function PolicyEditor() {
  const { t } = useI18n();
  const [view, setView] = useState<RuntimeResponse<"get_policy"> | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setView(await send({ type: "get_policy" }));
  }, []);

  useEffect(() => {
    void refresh();
    // The posture folds the policy record, the cutover flag, AND the pin (a revoke blocks it with the record
    // untouched), so any local change re-reads it rather than this page keeping the owner's key list.
    const onChanged = (_changes: Record<string, unknown>, area: string) => {
      if (area === "local") void refresh();
    };
    browser.storage.onChanged.addListener(onChanged);
    return () => browser.storage.onChanged.removeListener(onChanged);
  }, [refresh]);

  const restrict = async (overlay: PolicyOverlay) => {
    setBusy(true);
    setActionError(null);
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
  if (view.posture.kind === "preCutover") {
    return (
      <div className="py-1">
        <div className="text-[13px] font-medium">{t("policy.none_title")}</div>
        <p className="consequence mt-1">{t("policy.none_desc")}</p>
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

  const effective = view.posture.effective;
  return (
    <div className="py-1">
      <p className="consequence m-0">{t("policy.desc")}</p>
      {BOOL_POLICY_FIELDS.map((field) => (
        <BoolRow
          key={field}
          field={field}
          effective={effective}
          busy={busy}
          onRestrict={(overlay) => void restrict(overlay)}
        />
      ))}
      {MS_POLICY_FIELDS.map((field) => (
        <MsRow
          key={field}
          field={field}
          effective={effective}
          busy={busy}
          onRestrict={(overlay) => void restrict(overlay)}
        />
      ))}
      <ToolsRow
        effective={effective}
        busy={busy}
        onRestrict={(overlay) => void restrict(overlay)}
      />
      <p className="consequence mt-2">{t("policy.effective_note")}</p>
      <div
        role="alert"
        className={actionError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
      >
        {actionError}
      </div>
    </div>
  );
}

interface RowProps {
  effective: PolicyValues;
  busy: boolean;
  onRestrict: (overlay: PolicyOverlay) => void;
}

/** Whether applying `overlay` over the enforced values would relax any field: the host's own direction check
 * (policy::restricts_or_equal), run here so a relaxing control is disabled before it can ask. */
function wouldRelax(effective: PolicyValues, overlay: PolicyOverlay): boolean {
  return relaxedPolicyFields(foldPolicyOverlay(effective, overlay), effective).length > 0;
}

function BoolRow({ field, effective, busy, onRestrict }: RowProps & { field: BoolPolicyField }) {
  const { t } = useI18n();
  const id = useId();
  const checked = effective[field];
  const flipRelaxes = wouldRelax(effective, { [field]: !checked });
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
        disabled={busy || flipRelaxes}
        onCheckedChange={(next) => onRestrict({ [field]: next })}
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

function MsRow({ field, effective, busy, onRestrict }: RowProps & { field: MsPolicyField }) {
  const { t } = useI18n();
  const id = useId();
  const current = effective[field];
  const [draft, setDraft] = useState(String(current));
  useEffect(() => setDraft(String(current)), [current]);
  const candidate = parseDuration(draft);
  const changed = candidate !== null && candidate !== current;
  const relaxes = changed && wouldRelax(effective, { [field]: candidate });
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
            if (candidate !== null) onRestrict({ [field]: candidate });
          }}
          disabled={busy || !changed || relaxes}
        >
          {t("policy.apply")}
        </Button>
      </div>
    </div>
  );
}

function ToolsRow({ effective, busy, onRestrict }: RowProps) {
  const { t } = useI18n();
  const disabled = effective.disabledTools;
  const candidates = OP_NAMES.filter((op) => !disabled.includes(op));
  const [pick, setPick] = useState<string>("");
  return (
    <div className="border-b border-edge py-3 last:border-b-0">
      <div className="text-[13px] font-medium">{t("confirm.pf_disabledTools")}</div>
      {/* Re-enabling a tool is a relaxation: the chips carry no remove action, only the note. */}
      <div className="mt-1 flex flex-wrap items-center gap-1.5">
        {disabled.length === 0 && (
          <span className="text-[11px] text-text-3">{t("policy.tools_none")}</span>
        )}
        {disabled.map((tool) => (
          <span key={tool} className="chip-mono" title={t("policy.needs_presence")}>
            {tool}
          </span>
        ))}
      </div>
      <div className="mt-2 flex items-center gap-2">
        <Select value={pick} onValueChange={setPick}>
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
            onRestrict({ disabledTools: [...disabled, pick] });
            setPick("");
          }}
          disabled={busy || pick === "" || disabled.includes(pick)}
        >
          {t("policy.disable_tool")}
        </Button>
      </div>
    </div>
  );
}
