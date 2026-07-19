import { Check, Copy } from "lucide-react";
import { Fragment, useEffect, useRef, useState } from "react";
import { LanguagePicker } from "@/components/LanguagePicker";
import { ChipMono, Consequence, Dot, ErrorNote, ViewShell } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { api, errorText } from "@/lib/tauri";
import { useAppStore } from "@/store";

function CopyButton({ text, label }: { text: string; label?: string }) {
  const { t } = useI18n();
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  // the flash timer starts when the write settles and restarts on every
  // copy, so back-to-back copies each get their full 1.5s of feedback
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const flash = (kind: "copied" | "failed") => {
    setState(kind);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), 1500);
  };
  return (
    <Button
      size="sm"
      aria-label={label}
      aria-live="polite"
      onClick={() => {
        navigator.clipboard.writeText(text).then(
          () => flash("copied"),
          () => flash("failed"),
        );
      }}
    >
      {state === "copied" ? <Check size={11} aria-hidden /> : <Copy size={11} aria-hidden />}
      {state === "copied"
        ? t("common.copied")
        : state === "failed"
          ? t("common.copy_failed")
          : t("common.copy")}
    </Button>
  );
}

export function SetupView() {
  const { t } = useI18n();
  const setView = useAppStore((s) => s.setView);
  const status = useAppStore((s) => s.status);
  const snippet = useAsync(api.mcpSnippet);
  const cliTool = useAsync(api.cliToolStatus);
  const extension = useAsync(api.extensionInfo);
  const browsers = useAsync(api.browsersList);
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

  const browserDone = (browsers.data ?? []).some((b) => b.healthy);
  const cli = cliTool.data;
  const mcpParts: { text: string; k?: boolean }[] | undefined =
    snippet.data === undefined
      ? undefined
      : [
          { text: "{\n  " },
          { text: '"mcpServers"', k: true },
          { text: ": {\n    " },
          { text: '"chromium-bridge"', k: true },
          { text: ": {\n      " },
          { text: '"command"', k: true },
          { text: ": " },
          { text: JSON.stringify(snippet.data.hostPath) },
          { text: "\n    }\n  }\n}" },
        ];
  const mcpJson = mcpParts?.map((part) => part.text).join("");

  return (
    <ViewShell
      title={t("nav.setup")}
      sub={t("setup.sub")}
      foot={
        <>
          {status !== undefined && (
            <span className="foot-note tnum">
              chromium-bridge {status.version} - {status.os}/{status.arch}
            </span>
          )}
          <LanguagePicker />
        </>
      }
    >
      <div className="flex min-h-full flex-col">
        <ol className="flow">
          <li className={`flow-step ${browserDone ? "done" : "next"}`}>
            <span className="flow-mark" aria-hidden="true">
              {browserDone ? (
                <svg width="10" height="10" viewBox="0 0 12 12" fill="none" aria-hidden="true">
                  <path
                    d="M2.5 6.5 5 9l4.5-6"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              ) : (
                "1"
              )}
            </span>
            <div>
              <div className="flow-title">
                {t("setup.step1_title")}
                <span className="flow-state">
                  {browserDone ? t("setup.state_done") : t("setup.state_next")}
                </span>
              </div>
              <p className="flow-body">
                {browserDone ? t("setup.step1_done") : t("setup.step1_todo")}{" "}
                <button type="button" className="linkish" onClick={() => setView("browsers")}>
                  {t("nav.browsers")}
                </button>
                .
              </p>
            </div>
          </li>

          <li className={`flow-step${browserDone ? " next" : ""}`}>
            <span className="flow-mark" aria-hidden="true">
              2
            </span>
            <div>
              <div className="flow-title">
                {t("setup.step2_title")}
                <span className="flow-state">
                  {browserDone ? t("setup.state_next") : t("setup.state_todo")}
                </span>
              </div>
              <ol className="substeps">
                <li>
                  <span className="idx" aria-hidden="true">
                    a
                  </span>
                  <span>
                    {t("setup.step2_a_1")} <span className="mono">chrome://extensions</span>
                    {t("setup.step2_a_2")} <strong>{t("setup.step2_a_dev")}</strong>
                  </span>
                </li>
                <li>
                  <span className="idx" aria-hidden="true">
                    b
                  </span>
                  <span>
                    {t("setup.step2_b")} <strong>{t("setup.step2_b_btn")}</strong>
                  </span>
                </li>
                <li>
                  <span className="idx" aria-hidden="true">
                    c
                  </span>
                  {extension.data?.path != null ? (
                    <>
                      <ChipMono>{extension.data.path}</ChipMono>
                      <Button
                        size="sm"
                        onClick={() =>
                          void api.extensionReveal().catch((err: unknown) => {
                            setError(errorText(err));
                          })
                        }
                      >
                        {t("setup.ext_reveal")}
                      </Button>
                    </>
                  ) : extension.error !== undefined ? (
                    <span className="mono text-[11px] text-danger">{extension.error}</span>
                  ) : extension.data !== undefined ? (
                    <span className="text-pending">{t("setup.ext_missing")}</span>
                  ) : (
                    <span className="text-text-3">{t("common.loading")}</span>
                  )}
                </li>
              </ol>
              <p className="flow-body mt-[7px]">{t("setup.step2_note")}</p>
            </div>
          </li>

          <li className="flow-step">
            <span className="flow-mark" aria-hidden="true">
              3
            </span>
            <div>
              <div className="flow-title">
                {t("setup.step3_title")}
                <span className="flow-state">{t("setup.state_todo")}</span>
              </div>
              <p className="flow-body">{t("setup.step3_body")}</p>
              {snippet.error !== undefined && (
                <div className="mt-2">
                  <ErrorNote>{snippet.error}</ErrorNote>
                </div>
              )}
              {snippet.data !== undefined && mcpJson !== undefined && (
                <>
                  <div className="code-block mt-2">
                    <div className="code-head">
                      <span className="code-file">.mcp.json</span>
                      <CopyButton text={mcpJson} label={t("setup.copy_json")} />
                    </div>
                    <pre>
                      <code>
                        {mcpParts?.map((part, i) =>
                          part.k === true ? (
                            // biome-ignore lint/suspicious/noArrayIndexKey: static token list
                            <span key={i} className="k">
                              {part.text}
                            </span>
                          ) : (
                            // biome-ignore lint/suspicious/noArrayIndexKey: static token list
                            <Fragment key={i}>{part.text}</Fragment>
                          ),
                        )}
                      </code>
                    </pre>
                  </div>
                  <div className="mt-2 flex items-center gap-2">
                    <Consequence className="quiet m-0 flex-none">
                      {t("setup.step3_claude")}
                    </Consequence>
                    <span className="mono min-w-0 flex-1 [overflow-wrap:anywhere] text-[11px] text-text-3">
                      {snippet.data.command}
                    </span>
                    <CopyButton text={snippet.data.command} label={t("setup.copy_command")} />
                  </div>
                </>
              )}
            </div>
          </li>
        </ol>

        {error !== undefined && (
          <div className="mt-2">
            <ErrorNote>{error}</ErrorNote>
          </div>
        )}
        {cliTool.error !== undefined && (
          <div className="mt-2">
            <ErrorNote>{cliTool.error}</ErrorNote>
          </div>
        )}

        <div className="cli-row">
          <Dot
            tone={
              cli === undefined
                ? "idle"
                : cli.state === "installed"
                  ? cli.current
                    ? "idle"
                    : "pending"
                  : cli.state === "foreign"
                    ? "down"
                    : "idle"
            }
          />
          <span>
            {cli === undefined
              ? t("common.loading")
              : cli.state === "installed"
                ? cli.current
                  ? t("setup.cli_installed")
                  : t("setup.cli_stale")
                : cli.state === "foreign"
                  ? t("setup.cli_foreign")
                  : t("setup.cli_missing")}
          </span>
          {cli !== undefined && <span className="mono">{cli.path}</span>}
          <span className="spacer" />
          {cli?.state === "missing" && (
            <Button
              size="sm"
              variant="primary"
              disabled={busy}
              onClick={() => void cliAct(api.cliToolInstall)}
            >
              {busy ? t("common.working") : t("setup.cli_install")}
            </Button>
          )}
          {cli?.state === "installed" && !cli.current && (
            <Button size="sm" disabled={busy} onClick={() => void cliAct(api.cliToolInstall)}>
              {t("setup.cli_update")}
            </Button>
          )}
          {cli?.state === "installed" && (
            <Button size="sm" disabled={busy} onClick={() => void cliAct(api.cliToolUninstall)}>
              {t("setup.cli_uninstall")}
            </Button>
          )}
        </div>
        {cli?.state === "installed" && (
          <Consequence className="quiet mt-1.5 text-right">
            {t("setup.cli_uninstall_consequence", [cli.path])}
          </Consequence>
        )}
      </div>
    </ViewShell>
  );
}
