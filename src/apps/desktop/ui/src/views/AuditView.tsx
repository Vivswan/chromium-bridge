import { Card, ErrorNote, Mono } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { api, isUnrecognized } from "@/lib/tauri";

const LIMIT = 200;

function formatTime(tsMs: number): string {
  const d = new Date(tsMs);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}`;
}

export function AuditView() {
  const { t } = useI18n();
  const page = useAsync(() => api.auditRead(LIMIT));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-4">
        <p className="m-0 text-sm text-muted">{t("audit.intro")}</p>
        <div className="flex shrink-0 gap-2">
          <Button size="sm" onClick={page.reload}>
            {t("common.refresh")}
          </Button>
          <Button size="sm" onClick={() => void api.auditReveal()}>
            {t("audit.reveal")}
          </Button>
        </div>
      </div>

      {page.error !== undefined && <ErrorNote>{page.error}</ErrorNote>}
      {page.data !== undefined && page.data.unrecognized > 0 && (
        <ErrorNote>{t("audit.unrecognized", [String(page.data.unrecognized)])}</ErrorNote>
      )}

      <Card>
        {page.data === undefined ? (
          <p className="m-0 text-sm text-muted">{t("common.loading")}</p>
        ) : page.data.lines.length === 0 ? (
          <p className="m-0 text-sm text-muted">{t("audit.empty")}</p>
        ) : (
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="pb-2 pr-3 font-medium">{t("audit.time")}</th>
                <th className="pb-2 pr-3 font-medium">{t("audit.kind")}</th>
                <th className="pb-2 font-medium">{t("audit.details")}</th>
              </tr>
            </thead>
            <tbody>
              {page.data.lines.map((line, i) =>
                isUnrecognized(line) ? (
                  // biome-ignore lint/suspicious/noArrayIndexKey: append-only log lines have no id
                  <tr key={i} className="border-t border-edge-soft">
                    <td className="py-1.5 pr-3 text-xs text-faint">-</td>
                    <td colSpan={2} className="py-1.5 text-xs text-danger">
                      {t("audit.unrecognized_row")}
                    </td>
                  </tr>
                ) : (
                  // biome-ignore lint/suspicious/noArrayIndexKey: append-only log lines have no id
                  <tr key={i} className="border-t border-edge-soft align-top">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-xs text-muted">
                      {formatTime(line.ts_ms)}
                    </td>
                    <td className="whitespace-nowrap py-1.5 pr-3 font-mono text-xs">
                      {line.kind}
                      {line.outcome !== undefined && (
                        <span
                          className={
                            line.outcome === "ok"
                              ? "text-brand"
                              : line.outcome === "refused" || line.outcome === "error"
                                ? "text-danger"
                                : "text-muted"
                          }
                        >
                          {" "}
                          {line.outcome}
                        </span>
                      )}
                    </td>
                    <td className="break-all py-1.5 font-mono text-xs text-muted">
                      {[
                        line.surface !== undefined ? `surface=${line.surface}` : undefined,
                        line.tool !== undefined ? `tool=${line.tool}` : undefined,
                        line.name !== undefined ? `name=${line.name}` : undefined,
                        line.code !== undefined ? `code=${line.code}` : undefined,
                        line.detail !== undefined ? `detail=${line.detail}` : undefined,
                        line.dur_ms !== undefined ? `dur_ms=${line.dur_ms}` : undefined,
                        line.dropped !== undefined ? `dropped=${line.dropped}` : undefined,
                      ]
                        .filter((s) => s !== undefined)
                        .join(" ")}
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        )}
      </Card>

      {page.data !== undefined && <Mono className="text-faint">{page.data.path}</Mono>}
    </div>
  );
}
