import {
  type ConfirmKind,
  type ConfirmPayload,
  ConfirmPayloadSchema,
  isHardwareGated,
  isPolicyFieldName,
  type OpName,
  type PolicyFieldName,
} from "@chromium-bridge/shared";
import { useEffect, useRef, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import type { MessageKey } from "@/lib/i18n";

// The confirmation window (ADR-0027): an extension-owned page a guarded page
// cannot reach, read, or click. It fetches the pending payload by the id in
// its URL, renders WHAT is being approved (text only), and reports the
// verdict via confirm_resolve - which the router accepts only from this exact
// document. Escape / closing the window / timeout all deny; Allow arms after
// a short delay so stray input cannot approve.
//
// Control Tower restyle: the security behavior above is untouched. The exact
// payload is the ONLY contained surface; Deny is the filled, easy default.

const ARM_DELAY_MS = 600;

const HEADLINE_KEY: Record<ConfirmKind, MessageKey> = {
  click: "confirm.h_click",
  press: "confirm.h_press",
  select: "confirm.h_select",
  eval: "confirm.h_eval",
  tab_close: "confirm.h_tab_close",
  upload: "confirm.h_upload",
  policy_relax: "confirm.h_policy_relax",
};

// One consequence line per control (design law): every kind states what
// Allow does and that Deny changes nothing.
const WARNING_KEY: Record<ConfirmKind, MessageKey> = {
  click: "confirm.warn_click",
  press: "confirm.warn_press",
  select: "confirm.warn_select",
  eval: "confirm.warn_eval",
  tab_close: "confirm.warn_tab_close",
  upload: "confirm.warn_upload",
  policy_relax: "confirm.warn_policy_relax",
};

// The meta chip speaks the catalogue's tool vocabulary (page_click, ...), the
// same names the options grid and the audit trail use - never the internal
// ConfirmKind spelling. `satisfies` pins every value to the generated OpName
// union, so a catalogue rename breaks this map at compile time instead of
// leaving the security chip showing a stale name. policy_relax is the one
// kind that is not a tool call: its chip shows the wire frame name instead
// (chipName below).
const TOOL_NAME = {
  click: "page_click",
  press: "page_press",
  select: "page_select",
  eval: "page_eval",
  tab_close: "tab_close",
  upload: "page_upload",
} as const satisfies Record<Exclude<ConfirmKind, "policy_relax">, OpName>;

// ADR-0032 Lane U: the policy_relax detail carries the relaxing fields' WIRE
// names, one per line; this map renders each beside its localized label.
// `satisfies` pins the map to the generated field catalogue, so a policy
// field added in the Rust core breaks this at compile time instead of
// showing an unlabeled wire name in the approval window.
const POLICY_FIELD_LABEL = {
  cdpMode: "confirm.pf_cdpMode",
  fileUploadEnabled: "confirm.pf_fileUploadEnabled",
  handleDialogEnabled: "confirm.pf_handleDialogEnabled",
  pageEvalEnabled: "confirm.pf_pageEvalEnabled",
  confirmHighRiskClick: "confirm.pf_confirmHighRiskClick",
  confirmPageEval: "confirm.pf_confirmPageEval",
  touchIdConfirm: "confirm.pf_touchIdConfirm",
  confirmTabClose: "confirm.pf_confirmTabClose",
  warnPreciseSnapshot: "confirm.pf_warnPreciseSnapshot",
  evalMask: "confirm.pf_evalMask",
  hostReverifyMs: "confirm.pf_hostReverifyMs",
  confirmGraceMs: "confirm.pf_confirmGraceMs",
  clickToastTimeoutMs: "confirm.pf_clickToastTimeoutMs",
  evalToastTimeoutMs: "confirm.pf_evalToastTimeoutMs",
  disabledTools: "confirm.pf_disabledTools",
} as const satisfies Record<PolicyFieldName, MessageKey>;

// The contained payload text for a policy_relax confirmation: each wire
// field name from the detail beside its localized label. Two line shapes
// arrive (policy-approval.ts): a bare field name (the relaxing fields of a
// later document) or `field = value` (the FULL value set of the first-ever
// document, U2). An unrecognized line (a field this build does not know)
// stays verbatim - showing the raw wire name is the honest fallback, never
// dropping a granted field from what the user approves.
function policyRelaxLines(detail: string, t: (k: MessageKey) => string): string {
  return detail
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => {
      const eq = line.indexOf(" = ");
      const name = eq === -1 ? line : line.slice(0, eq);
      return isPolicyFieldName(name) ? `${line} - ${t(POLICY_FIELD_LABEL[name])}` : line;
    })
    .join("\n");
}

async function resolve(id: string, approved: boolean): Promise<void> {
  try {
    await browser.runtime.sendMessage({ type: "confirm_resolve", id, approved });
  } catch {
    // SW gone; the request is already lost (denied).
  }
  window.close();
}

// The panic exit: one SW-side message denies EVERYTHING pending (this
// confirmation, the queue, new arrivals) and engages the kill switch (deny
// settles first, synchronously, in the SW - see the router). The SW's
// dismiss closes this window right after the deny; the engage continues in
// the SW, so nothing is lost with the document.
async function denyAndKill(): Promise<void> {
  try {
    await browser.runtime.sendMessage({ type: "confirm_deny_kill" });
  } catch {
    // SW gone; the request is already lost (denied) and nothing can act.
  }
  window.close();
}

// Same glyph as the popup/options kill rows: the one red vocabulary.
function KillIcon({ size = 10 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 1.5v6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <path
        d="M4.5 3.6a6 6 0 1 0 7 0"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

function fmtCountdown(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

// The which-gate-held strip: plain mono segments (dot + gate name) joined by
// hairlines - the anti-spoof signature a page cannot fake outside this window.
// The CLIENT segment stays idle/neutral: this window cannot see client
// attestation (that check lives host-side), so it never overclaims - the
// same semantics as the popup's micro pipeline. `hostUnattested` (the
// policy_relax kind) keeps the HOST segment idle too: an unsigned push on an
// unpinned extension proves nothing about the host, and a "passed" dot there
// would overclaim exactly the identity this approval exists to compensate.
function FiringStrip({
  hardware,
  hostUnattested,
  t,
}: {
  hardware: boolean;
  hostUnattested: boolean;
  t: (k: MessageKey) => string;
}) {
  const seg = (state: "passed" | "held" | "idle", label: string) => (
    <span
      className={`inline-flex flex-none items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.07em] ${
        state === "held" ? "text-pending" : state === "passed" ? "text-text-2" : "text-text-3"
      }`}
    >
      <span
        className={`status-dot ${state === "held" ? "pending" : state === "passed" ? "live" : ""}`}
      />
      {label}
    </span>
  );
  const link = (on: boolean) => (
    <span className={`h-px flex-1 ${on ? "bg-live-edge" : "bg-edge-strong"}`} />
  );
  return (
    <div className="flex items-center gap-2" role="img" aria-label={t("confirm.gate_strip_label")}>
      {seg("idle", t("confirm.gate_client"))}
      {link(false)}
      {hardware ? (
        <>
          {seg("held", t("confirm.gate_host_held"))}
          {link(false)}
          {seg("idle", t("confirm.gate_browser"))}
        </>
      ) : (
        <>
          {seg(hostUnattested ? "idle" : "passed", t("confirm.gate_host"))}
          {link(!hostUnattested)}
          {seg("held", t("confirm.gate_browser_held"))}
        </>
      )}
    </div>
  );
}

export function ConfirmApp() {
  const { t } = useI18n();
  const [payload, setPayload] = useState<ConfirmPayload | null | "loading">("loading");
  const [armed, setArmed] = useState(false);
  const [left, setLeft] = useState(0);
  // The countdown bar's full scale: seconds remaining when the payload landed.
  const initialLeft = useRef(0);
  // When this window appeared: the footer anchor that ties the prompt to the
  // audit trail's timestamps.
  const [openedAt] = useState(() => Date.now());
  // The footer's engage control fired: disabled from the first click (the SW
  // closes this window moments later; no second click, no release here).
  const [killBusy, setKillBusy] = useState(false);

  useEffect(() => {
    const id = new URLSearchParams(location.search).get("id") || "";
    void browser.runtime.sendMessage({ type: "confirm_ready", id }).then(
      (resp: { payload?: unknown } | undefined) => {
        const parsed = ConfirmPayloadSchema.safeParse(resp?.payload ?? null);
        setPayload(parsed.success ? parsed.data : null);
      },
      () => setPayload(null),
    );
  }, []);

  useEffect(() => {
    if (payload === "loading" || payload === null) return;
    initialLeft.current = Math.max(1, Math.ceil((payload.deadline - Date.now()) / 1000));
    const armTimer = setTimeout(() => setArmed(true), ARM_DELAY_MS);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void resolve(payload.id, false);
    };
    document.addEventListener("keydown", onKey);
    const tick = () => setLeft(Math.max(0, Math.ceil((payload.deadline - Date.now()) / 1000)));
    tick();
    const countdown = setInterval(tick, 500);
    return () => {
      clearTimeout(armTimer);
      clearInterval(countdown);
      document.removeEventListener("keydown", onKey);
    };
  }, [payload]);

  if (payload === "loading") {
    return <div className="p-5 text-sm text-text-3">{t("confirm.title")}</div>;
  }
  if (payload === null) {
    return <div className="p-10 text-center text-sm text-text-3">{t("confirm.gone")}</div>;
  }

  const warnKey = WARNING_KEY[payload.kind];
  // ADR-0031: a hardware-gated confirmation renders display-only. Approval
  // is the Touch ID tap on the host's system prompt (the service refuses a
  // window-side approval); Deny stays - removing capability is friction-free.
  // The payload union confines `hardware` to the eval/upload arms; the shared
  // narrowing helper is the one reader.
  const hardware = isHardwareGated(payload);
  // ADR-0032 Lane U: an unsigned policy relaxation on an unpinned extension.
  // No page is involved (origin/tabTitle are ""), the chip names the wire
  // frame instead of a tool, and the host segment renders unattested.
  const policyRelax = payload.kind === "policy_relax";
  // The headline names the TARGET site plainly (the requester is the paired
  // MCP client, which this payload cannot attest - so the copy asks about
  // the action's destination, never "X wants"); the chip keeps the exact origin.
  const subject = payload.origin.replace(/^https?:\/\//, "") || t("confirm.this_page");
  const barFraction = initialLeft.current > 0 ? left / initialLeft.current : 0;

  return (
    <div className="confirm-surface flex h-screen flex-col gap-3 bg-surface-0 p-4 text-text-1">
      {/* Everything page-influenced (origin, title, payload) lives in this
          region; the decision controls and notes below sit OUTSIDE it, so no
          hostile-length content can push them off the h-screen root. Under
          pressure the payload box shrinks first (it is the only shrinkable
          child); only if the REST still cannot fit does the region itself
          scroll, as the final bound. flex-1 also absorbs the slack under
          small payloads, keeping the actions pinned to the bottom. */}
      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
        <FiringStrip hardware={hardware} hostUnattested={policyRelax} t={t} />
        <p className="text-[11px] leading-snug text-text-3">
          {t(hardware ? "confirm.spoof_note_host" : "confirm.spoof_note_browser")}{" "}
          {t("confirm.spoof_note_drawn")}
        </p>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-text-3">
          {t("confirm.via")}
          <span className="chip-mono">
            {payload.kind === "policy_relax" ? "policy_current" : TOOL_NAME[payload.kind]}
          </span>
          {payload.kind === "click" && (
            <span className="pill pill-pending">{t("confirm.high_risk")}</span>
          )}
        </div>

        <h1 className="m-0 text-base font-semibold leading-snug tracking-tight">
          {policyRelax ? t(HEADLINE_KEY[payload.kind]) : t(HEADLINE_KEY[payload.kind], [subject])}
        </h1>
        {/* No page is involved in a policy_relax: the origin/title row would
            render empty chips, so it is omitted rather than faked. */}
        {!policyRelax && (
          <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs text-text-2">
            <span className="chip-mono chip-wrap max-w-full">{payload.origin}</span>
            {/* the title is page-controlled context, not the grant: clamp it so
                a hostile document.title cannot crowd out the payload */}
            <span className="line-clamp-2 min-w-0 text-text-3">&quot;{payload.tabTitle}&quot;</span>
          </div>
        )}

        {/* the exact payload IS the decision: the only contained surface.
            Sized to content for small payloads, but the only child allowed
            to shrink: a long payload scrolls inside this box while the rest
            of the region stays put. Rendered whitespace-pre: source line
            breaks are preserved and long lines scroll horizontally, so a
            display wrap can never be mistaken for a source newline. For
            policy_relax the payload is the relaxing fields' wire names - or,
            for the first-ever document, the full `field = value` set (U2) -
            each rendered beside its localized label; the empty-detail
            fallback is defensive only (U2 makes it unreachable) and its copy
            tells the user to deny. */}
        <pre className="code-block m-0 min-h-[60px] shrink whitespace-pre px-3 py-2.5">
          {policyRelax
            ? policyRelaxLines(payload.detail, t) || t("confirm.policy_relax_none")
            : payload.detail}
        </pre>

        <p className="consequence">{t(warnKey)}</p>

        <div>
          <div className="flex items-baseline justify-between text-[11px] text-text-3">
            <span>{t("confirm.idle_note")}</span>
            <span className="tnum font-mono">{t("confirm.countdown", [fmtCountdown(left)])}</span>
          </div>
          <div className="mt-1.5 h-0.5 overflow-hidden rounded-full bg-surface-4">
            {/* transform-only motion: scaleX drains smoothly between the 500ms
                ticks (width would be a stepped layout animation) */}
            <div
              className="h-full origin-left bg-pending transition-transform duration-500 ease-linear"
              style={{ transform: `scaleX(${barFraction})` }}
            />
          </div>
        </div>
      </div>

      <div className="flex gap-2.5">
        <Button
          variant="primary"
          className="flex-1 py-2 text-[13px]"
          autoFocus
          onClick={() => void resolve(payload.id, false)}
        >
          {t("confirm.deny")} <span className="kbd">esc</span>
        </Button>
        {hardware ? (
          <span
            role="status"
            className="inline-flex flex-1 items-center justify-center gap-1.5 py-2 text-xs font-semibold text-pending"
          >
            <svg width="11" height="12" viewBox="0 0 12 14" fill="none" aria-hidden="true">
              <path
                d="M6 3.5c2.5 0 4 1.8 4 4.2 0 2-.4 3.6-1 4.8M6 6c1.3 0 2 .9 2 2.1 0 1.6-.3 2.9-.8 3.9M6 8.6c0 1.6-.4 2.9-1.1 3.9M3 5.2C2.3 6 2 7 2 8c0 1.3-.2 2.4-.6 3.3"
                stroke="currentColor"
                strokeWidth="1.1"
                strokeLinecap="round"
              />
            </svg>
            {t("confirm.touchid_wait")}
          </span>
        ) : (
          <Button
            className="flex-1 py-2 text-[13px]"
            disabled={!armed}
            onClick={() => void resolve(payload.id, true)}
          >
            {t("confirm.allow")}
          </Button>
        )}
      </div>
      <p className="text-[11px] leading-snug text-text-3">
        {t(hardware ? "confirm.hardware_note" : "confirm.arm_note", [String(ARM_DELAY_MS)])}
      </p>

      {/* Footer, OUTSIDE the scroll region like the actions above it: the
          request-id/timestamp line plus the compact panic exit (ADR-0030's
          one-action brake, present on every surface). Engage only, never
          release; last in DOM order so Deny keeps the default focus. It
          denies this request first and then severs everything - both are
          capability reduction, so it stays available in hardware mode too. */}
      <div className="flex items-center gap-2 border-t border-edge pt-2 font-mono text-[10px] text-text-3">
        <span className="min-w-0 flex-1 truncate">{t("confirm.request_id", [payload.id])}</span>
        <span className="tnum whitespace-nowrap">{new Date(openedAt).toLocaleString()}</span>
        <Button
          variant="danger"
          className="flex-none gap-1 px-2 py-0.5 font-sans text-[10px]"
          disabled={killBusy}
          title={t("confirm.kill_note")}
          aria-describedby="kill-note"
          onClick={() => {
            setKillBusy(true);
            void denyAndKill();
          }}
        >
          <KillIcon />
          {t("kill.engage")}
        </Button>
        {/* the consequence, readable by assistive tech (title alone is not) */}
        <span id="kill-note" className="sr-only">
          {t("confirm.kill_note")}
        </span>
      </div>
    </div>
  );
}
