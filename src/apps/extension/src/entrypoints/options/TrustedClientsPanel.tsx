import type { TrustedClient } from "@chromium-bridge/shared/generated/envelope";
import {
  type AnchorFault,
  anchorFault,
  ClientAnchorSchema,
  ClientNameSchema,
  type RuntimeResponse,
} from "@chromium-bridge/shared/runtime-msg";
import { useCallback, useEffect, useId, useState } from "react";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import type { MessageKey } from "@/lib/i18n";
import { send } from "@/lib/messages";
import { PresenceActStatus } from "./PresenceActStatus";
import { usePresenceAct } from "./usePresenceAct";

// The trusted-client panel: the MCP-client harnesses this machine's bridge admits, a revoke per entry, and the
// form that trusts one. Revoking takes effect immediately at the enforcement point: the allowlist is rewritten
// and the revocation epoch bumped in one critical section, so a live broker drops the client's connections and
// refuses its re-attach. Trusting one GRANTS capability, so the host answers with its presence request, as
// `pair-client` asks for the typed phrase; the page names an explicit anchor only, since a browser has no parent
// process to measure. The list lives host-side; reads and writes go through the SW router to the native host, so
// this panel shows a not-connected state when no host is up.
type AnchorKind = TrustedClient["anchor"]["kind"];

/** The sentence for each anchor fault: the CLI's (ipc::identity) for the three it can print, the page's own
 * for the unpaired surrogate no terminal types. */
const ANCHOR_FAULT_KEYS: Readonly<Record<AnchorFault, MessageKey>> = {
  hash_grammar: "clients.pair_invalid_hash",
  signer_empty: "clients.pair_invalid_signer_empty",
  signer_nul: "clients.pair_invalid_signer_nul",
  signer_ill_formed: "clients.pair_invalid_signer_ill_formed",
};

export function TrustedClientsPanel() {
  const { t } = useI18n();
  const ids = { name: useId(), value: useId(), hash: useId(), signer: useId() };
  const [view, setView] = useState<RuntimeResponse<"get_clients"> | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<AnchorKind>("hash");
  const [value, setValue] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setView(await send({ type: "get_clients" }));
  }, []);
  const paired = useCallback(() => {
    setName("");
    setValue("");
    void refresh();
  }, [refresh]);
  const pairing = usePresenceAct(paired);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const revoke = async (clientName: string) => {
    if (!window.confirm(t("clients.revoke_confirm", [clientName]))) return;
    setBusy(true);
    setActionError(null);
    const r = await send({ type: "revoke_client", name: clientName });
    if (!r.ok) setActionError(t("clients.revoke_failed", [r.error]));
    await refresh();
    setBusy(false);
  };

  // The host's grammars, checked here so the refusal is shown as a sentence before anything is posted (the
  // router would otherwise answer "malformed runtime message").
  const pair = () => {
    setFormError(null);
    const parsedName = ClientNameSchema.safeParse(name.trim());
    if (!parsedName.success) {
      setFormError(t("clients.pair_invalid_name"));
      return;
    }
    const anchor = ClientAnchorSchema.safeParse({ kind, value: value.trim() });
    if (!anchor.success) {
      setFormError(t(ANCHOR_FAULT_KEYS[anchorFault(anchor.error)]));
      return;
    }
    void pairing.run(() =>
      send({ type: "pair_client", name: parsedName.data, anchor: anchor.data }),
    );
  };

  const anchorLabel = (anchorKind: AnchorKind) =>
    anchorKind === "signer" ? t("clients.anchor_signer") : t("clients.anchor_hash");
  const formBusy = busy || pairing.busy;

  return (
    <div className="py-1">
      <div className="flex items-start justify-between gap-3">
        <p className="consequence m-0">{t("clients.desc")}</p>
        <Button variant="ghost" onClick={() => void refresh()} disabled={formBusy}>
          {t("clients.refresh")}
        </Button>
      </div>

      {view === null && <div className="mt-2 text-xs text-text-3">{t("clients.loading")}</div>}

      {/* A read failure is unknown/degraded, not a denial: pending ink (red
          stays reserved for kill/deny/compromised), fail-closed wording. */}
      {view && !view.ok && (
        <div role="status" className="mt-2 text-xs font-semibold text-pending">
          {t("clients.error", [view.error])}
        </div>
      )}

      {view?.ok && view.enrolled === false && (
        <p className="consequence mt-2">{t("clients.unenrolled")}</p>
      )}

      {view?.ok && view.enrolled && view.clients.length === 0 && (
        <div className="mt-2 text-xs text-text-3">{t("clients.empty")}</div>
      )}

      {view?.ok && view.enrolled && view.clients.length > 0 && (
        <ul className="m-0 mt-1 list-none p-0">
          {view.clients.map((c) => (
            <li
              key={c.name}
              className="flex items-center gap-3 border-b border-edge py-2 last:border-b-0"
            >
              <div className="min-w-0 flex-1">
                <div className="font-mono text-xs font-semibold text-text-1">{c.name}</div>
                <div className="truncate font-mono text-[11px] text-text-3">
                  {anchorLabel(c.anchor.kind)}: {c.anchor.value}
                </div>
              </div>
              <Button variant="ghost" onClick={() => void revoke(c.name)} disabled={formBusy}>
                {t("clients.revoke")}
              </Button>
            </li>
          ))}
        </ul>
      )}

      <div
        role="alert"
        className={actionError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
      >
        {actionError}
      </div>

      {view?.ok && (
        <div className="mt-4">
          <div className="text-[13px] font-medium">{t("clients.pair_title")}</div>
          <p className="consequence mt-1">{t("clients.pair_desc")}</p>
          <fieldset
            disabled={formBusy}
            className="m-0 mt-2 flex min-w-0 flex-wrap items-end gap-3 border-0 p-0"
          >
            <label htmlFor={ids.name} className="text-[11px] text-text-3">
              {t("clients.pair_name")}
              <input
                id={ids.name}
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="mt-0.5 block w-40 rounded-md border border-edge-strong bg-surface-1 px-2 py-1 font-mono text-xs text-text-1"
              />
            </label>
            <fieldset className="m-0 flex gap-3 border-0 p-0 text-[11px] text-text-3">
              {(["hash", "signer"] as const).map((k) => (
                <label key={k} htmlFor={ids[k]} className="flex items-center gap-1">
                  <input
                    id={ids[k]}
                    type="radio"
                    name={`${ids.name}-kind`}
                    checked={kind === k}
                    onChange={() => setKind(k)}
                  />
                  {k === "hash" ? t("clients.pair_kind_hash") : t("clients.pair_kind_signer")}
                </label>
              ))}
            </fieldset>
            <label htmlFor={ids.value} className="min-w-0 flex-1 text-[11px] text-text-3">
              {t("clients.pair_value")}
              <input
                id={ids.value}
                type="text"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                className="mt-0.5 block w-full rounded-md border border-edge-strong bg-surface-1 px-2 py-1 font-mono text-xs text-text-1"
              />
            </label>
            <Button onClick={pair} disabled={name === "" || value === ""}>
              {t("clients.pair")}
            </Button>
          </fieldset>
          <div
            role="alert"
            className={formError ? "mt-2 text-xs font-semibold text-danger" : "sr-only"}
          >
            {formError}
          </div>
          <PresenceActStatus
            presence={pairing}
            confirmLabel={t("clients.pair_confirm")}
            refused={(sentence) => t("clients.pair_failed", [sentence])}
          />
        </div>
      )}
    </div>
  );
}
