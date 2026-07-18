import { Fragment } from "react";
import { Card, Dot, ErrorNote, ViewShell } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { type AuditRecord, api, isUnrecognized } from "@/lib/tauri";

const LIMIT = 500;

function clock(tsMs: number): string {
  return new Date(tsMs).toLocaleTimeString(undefined, { hour12: false });
}

function dayLabel(tsMs: number): string {
  return new Date(tsMs).toLocaleDateString(undefined, {
    weekday: "short",
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
}

/** The record's subject (tool, origin, client name), highlighted in the
 * detail cell; everything else trails as key=value pairs, verbatim. */
function recordParts(line: AuditRecord): { obj?: string; rest: string } {
  const obj = line.tool ?? line.name ?? line.surface;
  const rest = [
    line.surface !== undefined && line.surface !== obj ? `surface=${line.surface}` : undefined,
    line.name !== undefined && line.name !== obj ? `name=${line.name}` : undefined,
    line.code !== undefined ? `code=${line.code}` : undefined,
    line.detail,
    line.dur_ms !== undefined ? `dur_ms=${line.dur_ms}` : undefined,
    line.dropped !== undefined ? `dropped=${line.dropped}` : undefined,
  ]
    .filter((s) => s !== undefined)
    .join(" - ");
  return { obj, rest };
}

function outcomeClass(outcome: string | undefined): string {
  switch (outcome) {
    case "ok":
      return " ok";
    case "refused":
    case "denied":
    case "error":
      return " denied";
    case "pending":
      return " pending";
    default:
      return "";
  }
}

export function AuditView() {
  const { t } = useI18n();
  const page = useAsync(() => api.auditRead(LIMIT));

  const lines = page.data?.lines ?? [];

  return (
    <ViewShell
      title={t("nav.audit")}
      sub={t("audit.sub")}
      scroll={false}
      right={
        <div className="flex flex-none items-center gap-2">
          <Button variant="ghost" onClick={page.reload}>
            {t("common.refresh")}
          </Button>
          <Button onClick={() => void api.auditReveal()}>{t("audit.reveal")}</Button>
        </div>
      }
      foot={
        page.data !== undefined && (
          <>
            <span className="foot-note">{page.data.path}</span>
            <span className="foot-note tnum">
              {t("audit.foot_count", [String(page.data.lines.length)])}
            </span>
          </>
        )
      }
    >
      {page.error !== undefined && (
        <div className="mb-2.5">
          <ErrorNote>{page.error}</ErrorNote>
        </div>
      )}
      {page.data !== undefined && page.data.unrecognized > 0 && (
        <div className="mb-2.5">
          <ErrorNote>{t("audit.unrecognized", [String(page.data.unrecognized)])}</ErrorNote>
        </div>
      )}

      <Card flush hero className="ledger" aria-label={t("audit.table_label")}>
        <div className="ledger-scroll">
          {page.data === undefined ? (
            <p className="m-0 p-3.5 text-xs text-text-3">{t("common.loading")}</p>
          ) : lines.length === 0 ? (
            <p className="m-0 p-3.5 text-xs text-text-3">{t("audit.empty")}</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th className="col-time" scope="col">
                    {t("audit.col_time")}
                  </th>
                  <th className="col-kind" scope="col">
                    {t("audit.col_kind")}
                  </th>
                  <th scope="col">{t("audit.col_detail")}</th>
                  <th className="col-outcome" scope="col">
                    {t("audit.col_outcome")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {lines.map((line, i) => {
                  const prev = i > 0 ? lines[i - 1] : undefined;
                  const day =
                    !isUnrecognized(line) &&
                    (prev === undefined ||
                      isUnrecognized(prev) ||
                      dayLabel(prev.ts_ms) !== dayLabel(line.ts_ms))
                      ? dayLabel(line.ts_ms)
                      : undefined;
                  if (isUnrecognized(line)) {
                    return (
                      // biome-ignore lint/suspicious/noArrayIndexKey: append-only log lines have no id
                      <tr key={i}>
                        <td className="t">-</td>
                        <td className="kind">?</td>
                        <td className="detail" colSpan={2} style={{ color: "var(--danger)" }}>
                          {t("audit.unrecognized_row")}
                        </td>
                      </tr>
                    );
                  }
                  const { obj, rest } = recordParts(line);
                  return (
                    // biome-ignore lint/suspicious/noArrayIndexKey: append-only log lines have no id
                    <Fragment key={i}>
                      {day !== undefined && (
                        <tr className="day-row">
                          <td colSpan={4}>{day}</td>
                        </tr>
                      )}
                      <tr className={line.outcome === "pending" ? "row-pending" : undefined}>
                        <td className="t tnum">{clock(line.ts_ms)}</td>
                        <td className="kind">{line.kind}</td>
                        <td className="detail">
                          {obj !== undefined && <span className="obj">{obj}</span>}
                          {obj !== undefined && rest !== "" && " - "}
                          {rest}
                        </td>
                        <td className={`outcome${outcomeClass(line.outcome)}`}>
                          {line.outcome === "pending" && <Dot tone="pending" />}
                          {line.outcome ?? "-"}
                        </td>
                      </tr>
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </ViewShell>
  );
}
