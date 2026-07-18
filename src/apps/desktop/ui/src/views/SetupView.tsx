import { useState } from "react";
import { LanguagePicker } from "@/components/LanguagePicker";
import { Card, ErrorNote, Mono, StatusDot } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { api, errorText } from "@/lib/tauri";

function CopyButton({ text }: { text: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  return (
    <Button
      size="sm"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? t("common.copied") : t("common.copy")}
    </Button>
  );
}

export function SetupView() {
  const { t } = useI18n();
  const snippet = useAsync(api.mcpSnippet);
  const cliTool = useAsync(api.cliToolStatus);
  const extension = useAsync(api.extensionInfo);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const cliAct = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
      cliTool.reload();
    }
  };

  const binDir = cliTool.data?.path.replace(/\/[^/]*$/, "") ?? "~/.local/bin";

  return (
    <div className="flex flex-col gap-4">
      <Card title={t("setup.mcp_title")}>
        <div className="flex flex-col gap-2">
          <p className="m-0 text-xs text-muted">{t("setup.mcp_hint")}</p>
          {snippet.error !== undefined && <ErrorNote>{snippet.error}</ErrorNote>}
          {snippet.data !== undefined && (
            <div className="flex items-start gap-2">
              <Mono className="flex-1">{snippet.data.command}</Mono>
              <CopyButton text={snippet.data.command} />
            </div>
          )}
        </div>
      </Card>

      <Card title={t("setup.cli_title")}>
        <div className="flex flex-col gap-3">
          <p className="m-0 text-xs text-muted">{t("setup.cli_hint", [binDir])}</p>
          {cliTool.error !== undefined && <ErrorNote>{cliTool.error}</ErrorNote>}
          {cliTool.data !== undefined && (
            <>
              <StatusDot
                tone={
                  cliTool.data.state === "installed"
                    ? cliTool.data.current
                      ? "ok"
                      : "warn"
                    : cliTool.data.state === "foreign"
                      ? "bad"
                      : "muted"
                }
              >
                {cliTool.data.state === "installed"
                  ? cliTool.data.current
                    ? t("setup.cli_installed")
                    : t("setup.cli_installed_stale")
                  : cliTool.data.state === "foreign"
                    ? t("setup.cli_foreign")
                    : t("setup.cli_missing")}
              </StatusDot>
              {cliTool.data.target !== null && <Mono>{cliTool.data.target}</Mono>}
              <div className="flex gap-2">
                {cliTool.data.state === "missing" && (
                  <Button
                    variant="primary"
                    disabled={busy}
                    onClick={() => void cliAct(api.cliToolInstall)}
                  >
                    {busy ? t("common.working") : t("setup.cli_install")}
                  </Button>
                )}
                {cliTool.data.state === "installed" && !cliTool.data.current && (
                  <Button disabled={busy} onClick={() => void cliAct(api.cliToolInstall)}>
                    {t("setup.cli_update")}
                  </Button>
                )}
                {cliTool.data.state === "installed" && (
                  <Button
                    variant="ghost"
                    disabled={busy}
                    onClick={() => void cliAct(api.cliToolUninstall)}
                  >
                    {t("setup.cli_uninstall")}
                  </Button>
                )}
              </div>
              {cliTool.data.state === "installed" && (
                <p className="m-0 text-xs text-faint">{t("setup.cli_path_note", [binDir])}</p>
              )}
            </>
          )}
          {error !== undefined && <ErrorNote>{error}</ErrorNote>}
        </div>
      </Card>

      <Card title={t("setup.ext_title")}>
        <div className="flex flex-col gap-2">
          <p className="m-0 text-xs text-muted">{t("setup.ext_hint")}</p>
          <ol className="m-0 flex list-decimal flex-col gap-1 pl-5 text-sm">
            <li>{t("setup.ext_step1")}</li>
            <li>{t("setup.ext_step2")}</li>
            <li>{t("setup.ext_step3")}</li>
          </ol>
          {extension.data?.path != null ? (
            <div className="flex items-start gap-2">
              <Mono className="flex-1">{extension.data.path}</Mono>
              <Button size="sm" onClick={() => void api.extensionReveal()}>
                {t("setup.ext_reveal")}
              </Button>
            </div>
          ) : (
            extension.data !== undefined && <ErrorNote>{t("setup.ext_missing")}</ErrorNote>
          )}
        </div>
      </Card>

      <Card title={t("setup.language_title")}>
        <LanguagePicker />
      </Card>
    </div>
  );
}
