import { useState } from "react";
import { Card, ErrorNote, Field, StatusDot, TextInput } from "@/components/ui/bits";
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

type AnchorKind = "hash" | "team_id";

export function ClientsView() {
  const { t } = useI18n();
  const clients = useAsync(api.clientsList);
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
  // is what Floor::AppConfirm asserts once phase8 lands (see the Rust seam).
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

  return (
    <div className="flex flex-col gap-4">
      <p className="m-0 text-sm text-muted">{t("clients.intro")}</p>
      {clients.error !== undefined && <ErrorNote>{clients.error}</ErrorNote>}

      {clients.data !== undefined && (
        <StatusDot tone={clients.data.posture === "enforced" ? "ok" : "warn"}>
          {clients.data.posture === "enforced"
            ? t("clients.posture_enforced")
            : t("clients.posture_unenrolled")}
        </StatusDot>
      )}

      <Card>
        {clients.data === undefined || clients.data.clients.length === 0 ? (
          <p className="m-0 text-sm text-muted">{t("clients.empty")}</p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="pb-2 pr-3 font-medium">{t("clients.name")}</th>
                <th className="pb-2 pr-3 font-medium">{t("clients.anchor")}</th>
                <th className="pb-2 pr-3 font-medium">{t("clients.added")}</th>
                <th className="pb-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {clients.data.clients.map((c) => (
                <tr key={c.name} className="border-t border-edge-soft">
                  <td className="py-2 pr-3 font-medium">{c.name}</td>
                  <td className="max-w-72 break-all py-2 pr-3 font-mono text-xs text-muted">
                    {c.anchorKind === "hash" ? t("clients.anchor_hash") : t("clients.anchor_team")}
                    {": "}
                    {c.anchorValue}
                  </td>
                  <td className="py-2 pr-3 text-xs text-muted">
                    {new Date(c.addedUnix * 1000).toLocaleDateString()}
                  </td>
                  <td className="py-2 text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy}
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

      <Card title={t("clients.add_title")}>
        <div className="flex flex-col gap-3">
          <p className="m-0 text-xs text-muted">{t("clients.add_hint")}</p>
          <div className="grid grid-cols-3 gap-3">
            <Field label={t("clients.name")}>
              <TextInput
                value={name}
                placeholder={t("clients.name_placeholder")}
                onChange={(e) => setName(e.target.value)}
              />
            </Field>
            <Field label={t("clients.anchor")}>
              <Select value={anchorKind} onValueChange={(v) => setAnchorKind(v as AnchorKind)}>
                <SelectTrigger aria-label={t("clients.anchor")}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="team_id">{t("clients.anchor_team")}</SelectItem>
                  <SelectItem value="hash">{t("clients.anchor_hash")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field
              label={anchorKind === "hash" ? t("clients.anchor_hash") : t("clients.anchor_team")}
            >
              <TextInput
                className="font-mono"
                value={anchorValue}
                placeholder={
                  anchorKind === "hash"
                    ? t("clients.value_placeholder_hash")
                    : t("clients.value_placeholder_team")
                }
                onChange={(e) => setAnchorValue(e.target.value)}
              />
            </Field>
          </div>
          <div className="flex items-center gap-3">
            <Button
              variant="primary"
              disabled={busy || name.trim() === "" || anchorValue.trim() === ""}
              onClick={() => setAddOpen(true)}
            >
              {busy ? t("common.working") : t("clients.add")}
            </Button>
            {addedBy !== undefined && (
              <StatusDot tone="ok">{t("clients.add_done", [authLabel(addedBy)])}</StatusDot>
            )}
          </div>
          <ConfirmDialog
            open={addOpen}
            onOpenChange={setAddOpen}
            title={t("clients.add_dialog_title")}
            body={t("clients.add_dialog_body", [name.trim()])}
            confirmLabel={t("clients.add_confirm")}
            busy={busy}
            onConfirm={() => void confirmAdd()}
          />
          <p className="m-0 text-xs text-faint">{t("clients.hint_cli")}</p>
        </div>
      </Card>

      {error !== undefined && <ErrorNote>{error}</ErrorNote>}
    </div>
  );
}
