import { Fragment, useState } from "react";
import {
  Card,
  Consequence,
  Dot,
  ErrorNote,
  Mono,
  Pill,
  TextInput,
  TouchIdChip,
  Twist,
  ViewShell,
} from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { browserAction } from "@/lib/browser-action";
import { browserDisplayName } from "@/lib/browser-names";
import { formatFingerprint } from "@/lib/fingerprint";
import { api, type BrowserRow, errorText } from "@/lib/tauri";

/** Break a filesystem path only after separators, so identity tokens (the
 * manifest filename) never fragment mid-string. */
function PathBreaks({ path }: { path: string }) {
  const parts = path.split("/");
  return (
    <>
      {parts.map((part, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: positional path segments
        <Fragment key={i}>
          {i > 0 && "/"}
          {i > 0 && <wbr />}
          {part}
        </Fragment>
      ))}
    </>
  );
}

export function BrowsersView() {
  const { t } = useI18n();
  const browsers = useAsync(api.browsersList);
  const enclave = useAsync(api.enclaveStatus);
  const [busy, setBusy] = useState<string>();
  const [report, setReport] = useState<string>();
  const [error, setError] = useState<string>();
  const [customDir, setCustomDir] = useState("");
  const [open, setOpen] = useState<string>();

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

  // Enclave ops prompt Touch ID from the signed host binary themselves; the
  // UI's job is only to show the transcript and re-read the state after.
  const enclaveAct = async (name: string, action: () => Promise<{ transcript: string }>) => {
    setBusy(name);
    setError(undefined);
    try {
      const outcome = await action();
      setReport(outcome.transcript);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(undefined);
      enclave.reload();
      browsers.reload();
    }
  };

  const rows = browsers.data ?? [];
  const registered = rows.filter((b) => b.healthy).length;
  const key = enclave.data?.key;
  const fingerprint = enclave.data?.fingerprint;

  const pillFor = (b: BrowserRow) => {
    if (!b.detected && b.code === "missing") return <Pill>{t("browsers.pill_not_detected")}</Pill>;
    switch (b.code) {
      case "ok":
        return <Pill tone="live">{t("browsers.pill_registered")}</Pill>;
      case "missing":
        return <Pill>{t("browsers.pill_unregistered")}</Pill>;
      case "foreign":
        return <Pill tone="danger">{t("browsers.pill_foreign")}</Pill>;
      default:
        return <Pill tone="pending">{t("browsers.pill_broken")}</Pill>;
    }
  };

  return (
    <ViewShell
      title={t("nav.browsers")}
      sub={t("browsers.sub")}
      right={
        <Pill tone={registered > 0 ? "live" : "idle"} dot className="tnum">
          {t("browsers.pill_count", [String(registered)])}
        </Pill>
      }
      foot={
        <>
          <span className="foot-note">
            com.vivswan.chromium_bridge.host
            {enclave.data !== undefined && ` - ${enclave.data.key_label}`}
          </span>
        </>
      }
    >
      <div className="flex flex-col gap-2.5">
        {browsers.error !== undefined && <ErrorNote>{browsers.error}</ErrorNote>}
        {enclave.error !== undefined && <ErrorNote>{enclave.error}</ErrorNote>}

        <Card flush hero aria-label={t("browsers.table_label")}>
          <table className="table">
            <thead>
              <tr>
                <th scope="col">{t("browsers.col_browser")}</th>
                <th scope="col">{t("browsers.col_state")}</th>
                <th scope="col">{t("browsers.col_manifest")}</th>
                <th scope="col">{t("browsers.col_pairing")}</th>
                <th scope="col" style={{ textAlign: "right" }}>
                  {t("browsers.col_actions")}
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((b) => {
                // a leftover/foreign registration must stay reachable even when the
                // browser itself is gone, so Remove registration remains available
                const expandable = b.detected || b.code !== "missing";
                const isOpen = open === b.key;
                const action = browserAction(b);
                return (
                  <Fragment key={b.key}>
                    <tr className={isOpen ? "open" : undefined}>
                      <td>
                        {expandable ? (
                          <button
                            className="name-wrap"
                            type="button"
                            aria-expanded={isOpen}
                            aria-controls={`detail-${b.key}`}
                            onClick={() => setOpen(isOpen ? undefined : b.key)}
                          >
                            <Twist />
                            <span>
                              <span className="browser-name">{browserDisplayName(b.key)}</span>
                              <span className="browser-profile">
                                {b.detected ? t("browsers.detected") : t("browsers.not_detected")}
                              </span>
                            </span>
                          </button>
                        ) : (
                          <div className="name-wrap">
                            <span style={{ width: 9, flex: "none" }} />
                            <span>
                              <span className="browser-name" style={{ color: "var(--text-3)" }}>
                                {browserDisplayName(b.key)}
                              </span>
                            </span>
                          </div>
                        )}
                      </td>
                      <td>{pillFor(b)}</td>
                      <td>
                        <div className={`mono path${b.healthy ? "" : " unwritten"}`}>
                          <PathBreaks path={b.location} />
                        </div>
                        <div className="path-note">
                          {b.code === "ok"
                            ? t("browsers.path_verified")
                            : b.code === "missing"
                              ? t("browsers.path_unwritten")
                              : b.state}
                        </div>
                      </td>
                      <td>
                        {expandable ? (
                          <>
                            <div className={`health-line${key === "present" ? "" : " off"}`}>
                              <Dot tone={key === "present" ? "live" : "idle"} />
                              {key === "present"
                                ? t("browsers.pairing_key_present")
                                : t("browsers.pairing_no_key")}
                            </div>
                            <div className={`health-line${b.healthy ? "" : " off"}`}>
                              {b.healthy
                                ? t("browsers.pairing_manifest_ok")
                                : t("browsers.pairing_on_connect")}
                            </div>
                          </>
                        ) : (
                          <div className="health-line off">-</div>
                        )}
                      </td>
                      <td className="actions-cell">
                        {action === "connect" && (
                          <Button
                            variant="primary"
                            size="sm"
                            disabled={busy !== undefined}
                            onClick={() => void act(b.key, () => api.browserRegister(b.key))}
                          >
                            {busy === b.key ? t("common.working") : t("browsers.connect")}
                          </Button>
                        )}
                        {action === "repair" && (
                          <Button
                            size="sm"
                            disabled={busy !== undefined}
                            onClick={() => void act(b.key, () => api.browserRegister(b.key))}
                          >
                            {busy === b.key ? t("common.working") : t("browsers.repair")}
                          </Button>
                        )}
                        {action === "none" && b.healthy && (
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={busy !== undefined}
                            onClick={() => {
                              browsers.reload();
                              enclave.reload();
                            }}
                          >
                            {t("browsers.verify")}
                          </Button>
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="row-detail" id={`detail-${b.key}`}>
                        <td colSpan={5}>
                          {key === "present" && fingerprint !== undefined ? (
                            <>
                              <div
                                className="fp-line"
                                role="img"
                                aria-label={`${t("browsers.fingerprint")}: ${formatFingerprint(fingerprint)}`}
                              >
                                {formatFingerprint(fingerprint)}
                              </div>
                              <Consequence className="mt-1.5">
                                {t("browsers.fp_compare_1", [browserDisplayName(b.key)])}{" "}
                                <strong>{t("browsers.fp_compare_2")}</strong>
                              </Consequence>
                              <p className="detail-meta">
                                {enclave.data?.key_label} - {t("browsers.fp_meta")}
                              </p>
                            </>
                          ) : (
                            <>
                              <div className="row-status">
                                <Dot tone={key === "none" ? "idle" : "down"} />
                                {key === "none"
                                  ? t("enclave.key_none")
                                  : key === "unsupported"
                                    ? t("enclave.key_unsupported")
                                    : key === "invalid"
                                      ? t("enclave.key_invalid")
                                      : t("enclave.key_error")}
                              </div>
                              {enclave.data?.detail !== undefined && (
                                <Mono className="mt-1.5">{enclave.data.detail}</Mono>
                              )}
                            </>
                          )}
                          <div className="detail-actions">
                            {key === "none" && (
                              <Button
                                variant="primary"
                                size="sm"
                                gated
                                disabled={busy !== undefined}
                                onClick={() =>
                                  void enclaveAct("pair", () => api.enclavePair(false))
                                }
                              >
                                {busy === "pair" ? t("common.working") : t("browsers.pair")}
                              </Button>
                            )}
                            {(key === "present" || key === "invalid" || key === "error") && (
                              <>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  gated
                                  disabled={busy !== undefined}
                                  onClick={() =>
                                    void enclaveAct("repair-key", () => api.enclavePair(true))
                                  }
                                >
                                  {busy === "repair-key"
                                    ? t("common.working")
                                    : t("browsers.repair_key")}
                                </Button>
                                <TouchIdChip />
                                <Button
                                  variant="danger"
                                  size="sm"
                                  disabled={busy !== undefined}
                                  onClick={() => void enclaveAct("revoke-key", api.enclaveRevoke)}
                                >
                                  {busy === "revoke-key"
                                    ? t("common.working")
                                    : t("browsers.revoke_key")}
                                </Button>
                              </>
                            )}
                            {key === "none" && <TouchIdChip />}
                            <Consequence>
                              {key === "none"
                                ? t("browsers.pair_consequence")
                                : t("browsers.revoke_consequence")}
                            </Consequence>
                          </div>
                          {b.code !== "missing" && (
                            <div className="detail-actions">
                              <Button
                                variant="ghost"
                                size="sm"
                                disabled={busy !== undefined}
                                onClick={() =>
                                  void act(`${b.key}-rm`, () => api.browserUnregister(b.key))
                                }
                              >
                                {busy === `${b.key}-rm`
                                  ? t("common.working")
                                  : t("browsers.unregister")}
                              </Button>
                              <Consequence>
                                {t("browsers.unregister_consequence", [browserDisplayName(b.key)])}
                              </Consequence>
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </Card>

        <div>
          <Consequence>
            <strong>{t("browsers.connect")}</strong> {t("browsers.connect_consequence")}
          </Consequence>
          <Consequence className="quiet mt-1">{t("browsers.restart_note")}</Consequence>
        </div>

        {error !== undefined && <ErrorNote>{error}</ErrorNote>}
        {report !== undefined && <Mono>{report}</Mono>}

        <details className="disclosure">
          <summary>
            <Twist />
            {t("browsers.custom_title")}
          </summary>
          <div className="disclosure-body">
            <Consequence>
              {t("browsers.custom_hint_1")} <strong>{t("browsers.custom_hint_2")}</strong>
            </Consequence>
            <div className="field-row">
              <TextInput
                className="mono"
                value={customDir}
                spellCheck={false}
                placeholder={t("browsers.custom_placeholder")}
                aria-label={t("browsers.custom_title")}
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
        </details>
      </div>
    </ViewShell>
  );
}
