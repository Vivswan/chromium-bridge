import { Cable } from "lucide-react";
import { useState } from "react";
import {
  Card,
  ChipMono,
  Consequence,
  Dot,
  ErrorNote,
  Field,
  Pill,
  SpecLabel,
  StatusDot,
  TextInput,
  TouchIdChip,
  TouchIdIcon,
  Twist,
  ViewShell,
} from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { authLabel } from "@/lib/auth-label";
import { api, errorText } from "@/lib/tauri";
import { useAppStore } from "@/store";

type AnchorKind = "hash" | "team_id";

export function ClientsView() {
  const { t } = useI18n();
  const clients = useAsync(api.clientsList);
  const status = useAppStore((s) => s.status);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [name, setName] = useState("");
  const [anchorKind, setAnchorKind] = useState<AnchorKind>("team_id");
  const [anchorValue, setAnchorValue] = useState("");
  const [addOpen, setAddOpen] = useState(false);
  const [addedBy, setAddedBy] = useState<string>();

  // Revocation is deliberately one click: it only reduces capability, and
  // keeping it friction-free is the security posture (ADR-0025/0030).
  const revoke = async (clientName: string) => {
    setBusy(true);
    setError(undefined);
    try {
      await api.clientRevoke(clientName);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
      clients.reload();
    }
  };

  // Presence-gated: invoked ONLY from the confirm dialog below. The dialog
  // is what Floor::AppConfirm asserts (see the Rust seam).
  const confirmAdd = async () => {
    setBusy(true);
    setError(undefined);
    setAddedBy(undefined);
    try {
      const auth = await api.clientPair(name.trim(), anchorKind, anchorValue.trim());
      setAddedBy(auth);
      setName("");
      setAnchorValue("");
      setAddOpen(false);
    } catch (err) {
      setError(errorText(err));
      setAddOpen(false);
    } finally {
      setBusy(false);
      clients.reload();
    }
  };

  const rows = clients.data?.clients ?? [];
  const enforced = clients.data?.posture === "enforced";

  const addForm = (
    <>
      <div className="form-grid">
        <Field label={t("clients.name")} htmlFor="client-name">
          <TextInput
            id="client-name"
            value={name}
            placeholder={t("clients.name_placeholder")}
            onChange={(e) => setName(e.target.value)}
          />
        </Field>
        <Field label={t("clients.anchor_kind")}>
          <Select value={anchorKind} onValueChange={(v) => setAnchorKind(v as AnchorKind)}>
            <SelectTrigger aria-label={t("clients.anchor_kind")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="team_id">team_id</SelectItem>
              <SelectItem value="hash">binary_hash</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field label={t("clients.anchor_value")} htmlFor="anchor-value">
          <TextInput
            id="anchor-value"
            className="mono"
            value={anchorValue}
            spellCheck={false}
            placeholder={
              anchorKind === "hash"
                ? t("clients.value_placeholder_hash")
                : t("clients.value_placeholder_team")
            }
            onChange={(e) => setAnchorValue(e.target.value)}
          />
        </Field>
      </div>
      <div className="mt-3 flex items-start gap-3.5">
        <Button
          variant="primary"
          gated
          className="flex-none"
          disabled={busy || name.trim() === "" || anchorValue.trim() === ""}
          onClick={() => setAddOpen(true)}
        >
          <TouchIdIcon size={12} />
          {busy ? t("common.working") : t("clients.add")}
        </Button>
        <Consequence>
          {t("clients.add_consequence_1")} <strong>{t("clients.add_consequence_2")}</strong>{" "}
          {t("clients.add_consequence_3")}
        </Consequence>
      </div>
      {addedBy !== undefined && (
        <StatusDot tone="live" className="mt-2 text-xs">
          {t("clients.add_done", [authLabel(addedBy)])}
        </StatusDot>
      )}
    </>
  );

  return (
    <ViewShell
      title={t("nav.clients")}
      sub={t("clients.sub")}
      right={
        <Pill tone={enforced && rows.length > 0 ? "live" : "idle"} dot className="tnum">
          {t("clients.pill_count", [String(rows.length)])}
        </Pill>
      }
      foot={
        status !== undefined && (
          <span className="foot-note tnum">
            chromium-bridge {status.version} - {status.os}/{status.arch}
          </span>
        )
      }
    >
      <div className="flex min-h-full flex-col gap-2.5">
        {clients.error !== undefined && <ErrorNote>{clients.error}</ErrorNote>}
        {error !== undefined && <ErrorNote>{error}</ErrorNote>}

        {clients.data !== undefined && !enforced && (
          <div className="banner banner-pending">
            <span className="banner-text">{t("clients.posture_unenrolled")}</span>
          </div>
        )}

        <Card flush hero aria-label={t("clients.table_label")}>
          <div className="card-head">
            <span className="card-title">{t("clients.table_label")}</span>
            <span className="mono tnum text-[11px] text-text-3">
              {t("clients.table_count", [String(rows.length)])}
            </span>
          </div>
          {clients.data === undefined ? (
            <p className="m-0 p-3.5 text-xs text-text-3">{t("common.loading")}</p>
          ) : rows.length === 0 ? (
            <div className="px-5 py-6 text-center">
              <div className="mb-2.5 inline-flex size-[34px] items-center justify-center rounded-full border border-edge-strong text-text-3">
                <Cable size={15} strokeWidth={1.6} aria-hidden />
              </div>
              <div className="text-[13px] font-semibold">{t("clients.empty_title")}</div>
              <p className="mx-auto mb-3 mt-1 max-w-[340px] text-xs text-text-2">
                {t("clients.empty_body")}
              </p>
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">{t("clients.col_client")}</th>
                  <th scope="col">{t("clients.col_anchor")}</th>
                  <th scope="col">{t("clients.col_added")}</th>
                  <th scope="col">
                    <span className="sr-only">{t("browsers.col_actions")}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((c) => (
                  <tr key={c.name}>
                    <td>
                      <div className="flex items-center gap-[7px] text-[13px] font-semibold text-text-1">
                        <Dot tone={enforced ? "live" : "idle"} />
                        {c.name}
                      </div>
                    </td>
                    <td>
                      <div className="flex flex-wrap items-center gap-[7px]">
                        <ChipMono>{c.anchorKind === "hash" ? "binary_hash" : "team_id"}</ChipMono>
                        <span className="mono break-all text-text-1">{c.anchorValue}</span>
                      </div>
                      <div className="mt-[3px] text-[11px] text-text-3">
                        {t("clients.anchor_checked")}
                      </div>
                    </td>
                    <td className="tnum whitespace-nowrap">
                      {new Date(c.addedUnix * 1000).toLocaleDateString()}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <Button
                        variant="danger"
                        size="sm"
                        disabled={busy}
                        aria-label={`${t("clients.revoke")} ${c.name}`}
                        onClick={() => void revoke(c.name)}
                      >
                        {t("clients.revoke")}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <div>
          <Consequence>
            {t("clients.revoke_consequence_1")} <strong>{t("clients.revoke_consequence_2")}</strong>{" "}
            {t("clients.revoke_consequence_3")}
          </Consequence>
          {enforced && (
            <Consequence className="quiet mt-1">{t("clients.unproven_note")}</Consequence>
          )}
        </div>

        {rows.length === 0 && clients.data !== undefined ? (
          <div className="mt-1">{addForm}</div>
        ) : (
          <details className="disclosure" aria-label={t("clients.add_title")}>
            <summary>
              <Twist />
              {t("clients.add_title")}
              <TouchIdChip />
            </summary>
            <div className="disclosure-body">{addForm}</div>
          </details>
        )}

        <section className="anchor-legend" aria-label={t("clients.legend_title")}>
          <SpecLabel className="col-span-full">{t("clients.legend_title")}</SpecLabel>
          <ChipMono>team_id</ChipMono>
          <span>{t("clients.legend_team")}</span>
          <ChipMono>binary_hash</ChipMono>
          <span>{t("clients.legend_hash")}</span>
        </section>

        <ConfirmDialog
          open={addOpen}
          onOpenChange={setAddOpen}
          title={t("clients.add_dialog_title")}
          body={t("clients.add_dialog_body", [name.trim()])}
          confirmLabel={t("clients.add_confirm")}
          busy={busy}
          onConfirm={() => void confirmAdd()}
        />
      </div>
    </ViewShell>
  );
}
