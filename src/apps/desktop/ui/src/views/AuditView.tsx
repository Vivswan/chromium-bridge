import { Fragment, useState } from "react";
import { Card, Dot, ErrorNote, ViewShell } from "@/components/ui/bits";
import { Button } from "@/components/ui/button";
import { useAsync } from "@/hooks/useAsync";
import { useI18n } from "@/hooks/useI18n";
import { resolvedShownRows } from "@/lib/audit-correlate";
import { type AuditRecord, api, errorText, isUnrecognized } from "@/lib/tauri";

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

/** Indices of CONFIRM_SHOWN rows a later confirm_allowed/confirm_denied
 * resolves. The correlation logic (an exact per-confirmation `cid` join, with
 * the old subject heuristic kept only as a pre-upgrade fallback) lives in
 * `@/lib/audit-correlate`, where it is unit-tested without this view. */

export function AuditView() {
  const { t } = useI18n();
  const page = useAsync(() => api.auditRead(LIMIT));
  const [revealError, setRevealError] = useState<string>();

  const lines = page.data?.lines ?? [];
  const resolved = resolvedShownRows(lines);
  const ledgerLabel = t("audit.table_label");
  // day headers group by the last SEEN day, skipping unrecognized lines, so
  // a corrupt record in the middle of a day cannot duplicate its header
  let lastDay: string | undefined;

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
          <Button
            onClick={() =>
              void api.auditReveal().catch((err: unknown) => {
                setRevealError(errorText(err));
              })
            }
          >
            {t("audit.reveal")}
          </Button>
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
      {revealError !== undefined && (
        <div className="mb-2.5">
          <ErrorNote>{revealError}</ErrorNote>
        </div>
      )}
      {page.data !== undefined && page.data.unrecognized > 0 && (
        <div className="mb-2.5">
          <ErrorNote>{t("audit.unrecognized", [String(page.data.unrecognized)])}</ErrorNote>
        </div>
      )}

      <Card flush hero className="ledger" aria-label={ledgerLabel}>
        {/* biome-ignore lint/a11y/noNoninteractiveTabindex: the scroll pane must be keyboard-reachable (WKWebView does not focus scrollers itself) */}
        {/* biome-ignore lint/a11y/useSemanticElements: role=region names the focusable scroll pane; the Card already provides the section landmark */}
        <div className="ledger-scroll" tabIndex={0} role="region" aria-label={ledgerLabel}>
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
                  const label = dayLabel(line.ts_ms);
                  const day = label !== lastDay ? label : undefined;
                  lastDay = label;
                  const { obj, rest } = recordParts(line);
                  // an open confirmation is derived from the correlation, not
                  // from a stored outcome: real confirm_shown records carry
                  // no outcome field at all
                  const resolvedShown = line.kind === "confirm_shown" && resolved.has(i);
                  const openShown = line.kind === "confirm_shown" && !resolved.has(i);
                  const pending = openShown || (line.outcome === "pending" && !resolvedShown);
                  return (
                    // biome-ignore lint/suspicious/noArrayIndexKey: append-only log lines have no id
                    <Fragment key={i}>
                      {day !== undefined && (
                        <tr className="day-row">
                          <td colSpan={4}>{day}</td>
                        </tr>
                      )}
                      <tr className={pending ? "row-pending" : undefined}>
                        <td className="t tnum">{clock(line.ts_ms)}</td>
                        <td className="kind">{line.kind}</td>
                        <td className="detail">
                          {obj !== undefined && <span className="obj">{obj}</span>}
                          {obj !== undefined && rest !== "" && " - "}
                          {rest}
                        </td>
                        <td
                          className={`outcome${outcomeClass(
                            resolvedShown ? "shown" : pending ? "pending" : line.outcome,
                          )}`}
                        >
                          {pending && <Dot tone="pending" />}
                          {resolvedShown
                            ? t("audit.outcome_shown")
                            : (line.outcome ?? (pending ? t("audit.outcome_pending") : "-"))}
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
