import { useState } from "react";
import { Card, ErrorNote, Mono, StatusDot, TextInput } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { browserAction } from "@/lib/browser-action";
import { api, errorText } from "@/lib/tauri";

export function BrowsersView() {
  const { t } = useI18n();
  const browsers = useAsync(api.browsersList);
  const [busy, setBusy] = useState<string>();
  const [report, setReport] = useState<string>();
  const [error, setError] = useState<string>();
  const [customDir, setCustomDir] = useState("");

  const act = async (name: string, action: () => Promise<string[] | string>) => {
    setBusy(name);
    setError(undefined);
    try {
      const lines = await action();
      setReport(Array.isArray(lines) ? lines.join("\n") : lines);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(undefined);
      browsers.reload();
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="m-0 text-sm text-muted">{t("browsers.intro")}</p>
      {browsers.error !== undefined && <ErrorNote>{browsers.error}</ErrorNote>}

      <Card>
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="text-left text-xs text-muted">
              <th className="pb-2 pr-3 font-medium" />
              <th className="pb-2 pr-3 font-medium">{t("browsers.state")}</th>
              <th className="pb-2 pr-3 font-medium">{t("browsers.location")}</th>
              <th className="pb-2 font-medium" />
            </tr>
          </thead>
          <tbody>
            {(browsers.data ?? []).map((b) => (
              <tr key={b.key} className="border-t border-edge-soft">
                <td className="py-2 pr-3">
                  <StatusDot tone={b.detected ? (b.healthy ? "ok" : "warn") : "muted"}>
                    <span className="font-medium capitalize">{b.key}</span>
                  </StatusDot>
                  <div className="pl-4 text-xs text-faint">
                    {b.detected ? t("browsers.detected") : t("browsers.not_detected")}
                  </div>
                </td>
                <td className="py-2 pr-3">{b.state}</td>
                <td className="max-w-64 break-all py-2 pr-3 font-mono text-xs text-muted">
                  {b.location}
                </td>
                <td className="py-2 text-right">
                  <div className="flex items-center justify-end gap-2">
                    {b.detected && b.healthy && (
                      <span className="text-xs text-muted">{t("browsers.connected")}</span>
                    )}
                    {browserAction(b) !== "none" && (
                      <Button
                        size="sm"
                        disabled={busy !== undefined}
                        onClick={() => void act(b.key, () => api.browserRegister(b.key))}
                      >
                        {busy === b.key
                          ? t("common.working")
                          : browserAction(b) === "connect"
                            ? t("browsers.connect")
                            : t("browsers.repair")}
                      </Button>
                    )}
                    {b.code !== "missing" && (
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={busy !== undefined}
                        onClick={() => void act(`${b.key}-rm`, () => api.browserUnregister(b.key))}
                      >
                        {t("browsers.unregister")}
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card title={t("browsers.custom_title")}>
        <div className="flex flex-col gap-2">
          <p className="m-0 text-xs text-muted">{t("browsers.custom_hint")}</p>
          <div className="flex gap-2">
            <TextInput
              className="flex-1 font-mono"
              value={customDir}
              placeholder="/path/NativeMessagingHosts"
              onChange={(e) => setCustomDir(e.target.value)}
            />
            <Button
              disabled={busy !== undefined || customDir.trim() === ""}
              onClick={() => void act("custom", () => api.manifestDirRegister(customDir.trim()))}
            >
              {t("browsers.custom_register")}
            </Button>
            <Button
              variant="ghost"
              disabled={busy !== undefined || customDir.trim() === ""}
              onClick={() =>
                void act("custom-rm", () => api.manifestDirUnregister(customDir.trim()))
              }
            >
              {t("browsers.custom_unregister")}
            </Button>
          </div>
        </div>
      </Card>

      {error !== undefined && <ErrorNote>{error}</ErrorNote>}
      {report !== undefined && <Mono>{report}</Mono>}
      <p className="m-0 text-xs text-faint">{t("browsers.restart_note")}</p>
    </div>
  );
}
