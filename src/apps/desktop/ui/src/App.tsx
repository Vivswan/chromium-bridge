import {
  Cable,
  Globe,
  LayoutGrid,
  Power,
  ScrollText,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useI18n } from "@/hooks/useI18n";
import { cn } from "@/lib/cn";
import type { MessageKey } from "@/lib/i18n";
import { api, errorText } from "@/lib/tauri";
import { useAppStore, type View } from "@/store";
import { AuditView } from "@/views/AuditView";
import { BrowsersView } from "@/views/BrowsersView";
import { ClientsView } from "@/views/ClientsView";
import { OverviewView } from "@/views/OverviewView";
import { SecurityView } from "@/views/SecurityView";
import { SetupView } from "@/views/SetupView";

const NAV: { view: View; labelKey: MessageKey; icon: typeof LayoutGrid }[] = [
  { view: "overview", labelKey: "nav.overview", icon: LayoutGrid },
  { view: "browsers", labelKey: "nav.browsers", icon: Globe },
  { view: "clients", labelKey: "nav.clients", icon: Cable },
  { view: "security", labelKey: "nav.security", icon: ShieldCheck },
  { view: "audit", labelKey: "nav.audit", icon: ScrollText },
  { view: "setup", labelKey: "nav.setup", icon: SlidersHorizontal },
];

export function App() {
  const { t } = useI18n();
  const view = useAppStore((s) => s.view);
  const setView = useAppStore((s) => s.setView);
  const status = useAppStore((s) => s.status);
  const refreshStatus = useAppStore((s) => s.refreshStatus);
  const setReleasedBy = useAppStore((s) => s.setReleasedBy);
  const [killBusy, setKillBusy] = useState(false);
  const [killError, setKillError] = useState<string>();

  // Shared status: fetched on start, refreshed on window focus (the cheap,
  // event-driven alternative to polling for a control panel).
  useEffect(() => {
    void refreshStatus();
    const onFocus = () => {
      // a refocus may follow CLI activity this app never observed, so a
      // prior release note may not describe the latest release - drop it.
      // Exception: focus churn from our own release flow's Touch ID sheet.
      if (useAppStore.getState().releaseInFlight === 0) setReleasedBy(undefined);
      void refreshStatus();
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [refreshStatus, setReleasedBy]);

  const engaged = status?.kill.state === "engaged";

  // The pinned panic entry. Engaging is one click from anywhere - it only
  // ever reduces capability. Release is presence-gated and lives on
  // Overview, so when engaged this button just takes you there.
  const onKill = async () => {
    if (engaged) {
      setView("overview");
      return;
    }
    setKillBusy(true);
    setKillError(undefined);
    // engaging invalidates any prior "released via X" note, even if the
    // status refresh below fails and leaves a stale kill state cached
    setReleasedBy(undefined);
    try {
      await api.killEngage();
    } catch (err) {
      setKillError(errorText(err));
    } finally {
      setKillBusy(false);
      void refreshStatus();
    }
  };

  return (
    <div className="flex h-full bg-surface-0">
      <nav className="sidebar" aria-label={t("nav.aria")}>
        <div className="mb-3 px-2.5 pt-1">
          <div className="text-[13px] font-semibold text-text-1">{t("app.title")}</div>
          {status !== undefined && (
            <div className="mono tnum text-[10px] text-text-3">v{status.version}</div>
          )}
        </div>
        {NAV.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.view}
              type="button"
              className={cn("nav-item", view === item.view && "active")}
              aria-current={view === item.view ? "page" : undefined}
              onClick={() => setView(item.view)}
            >
              <Icon size={14} strokeWidth={1.6} aria-hidden />
              {t(item.labelKey)}
            </button>
          );
        })}
        <div className="nav-spacer" />
        {killError !== undefined && (
          <p role="alert" className="mono m-0 mb-1 px-1 text-[10px] text-danger">
            {killError}
          </p>
        )}
        <button
          type="button"
          className={cn("nav-item nav-kill", engaged && "engaged")}
          disabled={killBusy}
          title={engaged ? undefined : t("overview.kill_consequence")}
          onClick={() => void onKill()}
        >
          <Power size={14} strokeWidth={1.8} aria-hidden />
          {engaged ? t("nav.kill_engaged") : t("nav.kill")}
        </button>
      </nav>
      <main className="main">
        {view === "overview" && <OverviewView />}
        {view === "browsers" && <BrowsersView />}
        {view === "clients" && <ClientsView />}
        {view === "security" && <SecurityView />}
        {view === "audit" && <AuditView />}
        {view === "setup" && <SetupView />}
      </main>
    </div>
  );
}
