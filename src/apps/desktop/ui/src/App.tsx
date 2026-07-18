import { useEffect } from "react";
import { useI18n } from "@/hooks/useI18n";
import { cn } from "@/lib/cn";
import type { MessageKey } from "@/lib/i18n";
import { useAppStore, type View } from "@/store";
import { AuditView } from "@/views/AuditView";
import { BrowsersView } from "@/views/BrowsersView";
import { ClientsView } from "@/views/ClientsView";
import { OverviewView } from "@/views/OverviewView";
import { PairingView } from "@/views/PairingView";
import { SetupView } from "@/views/SetupView";

const NAV: { view: View; labelKey: MessageKey }[] = [
  { view: "overview", labelKey: "nav.overview" },
  { view: "browsers", labelKey: "nav.browsers" },
  { view: "pairing", labelKey: "nav.pairing" },
  { view: "clients", labelKey: "nav.clients" },
  { view: "audit", labelKey: "nav.audit" },
  { view: "setup", labelKey: "nav.setup" },
];

const TITLE_KEY: Record<View, MessageKey> = {
  overview: "nav.overview",
  browsers: "browsers.title",
  pairing: "pairing.title",
  clients: "clients.title",
  audit: "audit.title",
  setup: "setup.title",
};

export function App() {
  const { t } = useI18n();
  const view = useAppStore((s) => s.view);
  const setView = useAppStore((s) => s.setView);
  const status = useAppStore((s) => s.status);
  const refreshStatus = useAppStore((s) => s.refreshStatus);

  // Shared status: fetched on start, refreshed on window focus (the cheap,
  // event-driven alternative to polling for a control panel).
  useEffect(() => {
    void refreshStatus();
    const onFocus = () => void refreshStatus();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refreshStatus]);

  return (
    <div className="flex h-full">
      <nav className="flex w-48 shrink-0 flex-col gap-1 border-r border-edge bg-surface p-3">
        <div className="mb-3 px-2">
          <div className="text-sm font-bold text-body">{t("app.title")}</div>
          {status !== undefined && <div className="text-xs text-faint">v{status.version}</div>}
        </div>
        {NAV.map((item) => (
          <button
            key={item.view}
            type="button"
            className={cn(
              "flex items-center justify-between rounded-lg px-3 py-2 text-left text-sm " +
                "cursor-pointer transition-colors",
              view === item.view
                ? "bg-edge-soft font-semibold text-body"
                : "text-muted hover:bg-edge-soft hover:text-body",
            )}
            aria-current={view === item.view ? "page" : undefined}
            onClick={() => setView(item.view)}
          >
            {t(item.labelKey)}
            {item.view === "overview" && status?.kill.state === "engaged" && (
              <span aria-hidden className="size-2 rounded-full bg-danger" />
            )}
          </button>
        ))}
        {status?.kill.state === "engaged" && (
          <div className="mt-auto rounded-lg border border-danger bg-danger-surface px-3 py-2 text-xs text-body">
            {t("overview.kill_engaged")}
          </div>
        )}
      </nav>
      <main className="flex-1 overflow-y-auto p-5">
        <h1 className="mb-4 mt-0 text-lg font-bold text-body">{t(TITLE_KEY[view])}</h1>
        {view === "overview" && <OverviewView />}
        {view === "browsers" && <BrowsersView />}
        {view === "pairing" && <PairingView />}
        {view === "clients" && <ClientsView />}
        {view === "audit" && <AuditView />}
        {view === "setup" && <SetupView />}
      </main>
    </div>
  );
}
