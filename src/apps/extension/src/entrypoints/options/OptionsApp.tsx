import { BRIDGE_PROTOCOL_VERSION, NATIVE_HOST_ID } from "@chromium-bridge/shared";
import { useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { LanguagePicker } from "@/components/app/LanguagePicker";
import { Section, SettingRow } from "@/components/app/SettingRow";
import { useI18n } from "@/hooks/useI18n";
import { useSettings } from "@/hooks/useSettings";
import type { UiLanguage } from "@/lib/i18n";
import { send } from "@/lib/messages";
import { AuditPanel } from "./AuditPanel";
import { EnrollmentPanel } from "./EnrollmentPanel";
import { KillSwitchPanel } from "./KillSwitchPanel";
import { SiteList } from "./SiteList";
import { TrustedClientsPanel } from "./TrustedClientsPanel";

// The options page: kill switch, host pairing, the allowlist, trusted
// clients, and the browser-owned toggles (allow-all-sites, tab grouping,
// language). Every write is event-driven (useSettings is backed by
// storage.onChanged), so there is no polling and no manual refresh; a change
// from any surface reflects here immediately.
//
// The security policy itself - the 15 host-owned fields (ADR-0032): eval,
// uploads, dialogs, CDP mode, the confirmation gates, timeouts, and per-tool
// disables - is NOT edited here. It is set in the Chromium Bridge app (or
// `chromium-bridge policy`), signed by the paired host key, and enforced by
// this extension; the Security section below says so where the toggles used
// to be. Kill RELEASE moved with it (the host refuses `kill_release` from
// the extension, ADR-0032 decision 6); engaging stays one click away.
//
// Control Tower: flat hairline-separated open sections, ordered by decision
// weight: kill switch, pairing, then the sites hero (the one choice that
// scopes what clients can touch). Amber and red stay reserved for pending
// and kill/deny - consequences are neutral ink.
export function OptionsApp() {
  const { t } = useI18n();
  const { settings, update } = useSettings();
  const [allowAllHeld, setAllowAllHeld] = useState<boolean | null>(null);

  // Deep links (e.g. the popup's "Start pairing") land on #<section-id>.
  useEffect(() => {
    const target = location.hash.slice(1);
    if (target) document.getElementById(target)?.scrollIntoView();
  }, []);

  // "Allow all sites" needs the <all_urls> host permission, requested inside
  // the change handler (a user gesture). Query the ACTUALLY-held permission on
  // mount so the toggle can't drift from reality.
  useEffect(() => {
    void browser.permissions
      .contains({ origins: ["<all_urls>"] })
      .then((held) => setAllowAllHeld(held));
  }, []);

  // Reconcile: if the setting says on but the permission is not held (revoked
  // externally), correct the stored setting to false so the background stops
  // bypassing per-site approval (it also checks the permission, but the UI
  // must not lie about the effective state).
  useEffect(() => {
    if (settings.allowAllSites && allowAllHeld === false) void update("allowAllSites", false);
  }, [settings.allowAllSites, allowAllHeld, update]);

  const effectiveAllowAll = settings.allowAllSites && allowAllHeld === true;

  const toggleAllowAll = async (on: boolean) => {
    if (on) {
      const granted = await browser.permissions
        .request({ origins: ["<all_urls>"] })
        .catch(() => false);
      if (!granted) {
        setAllowAllHeld(false);
        return; // declined: leave the setting off
      }
      setAllowAllHeld(true);
    } else {
      await browser.permissions.remove({ origins: ["<all_urls>"] }).catch(() => {});
      setAllowAllHeld(false);
    }
    await update("allowAllSites", on);
  };

  return (
    <div className="mx-auto max-w-[720px] px-6 pb-20 pt-8 text-sm">
      <header className="flex items-start justify-between gap-4 border-b border-edge pb-4">
        <div>
          <h1 className="m-0 text-base font-semibold tracking-tight">{t("options.title")}</h1>
          <div className="mt-0.5 text-xs text-text-3">{t("options.subtitle")}</div>
        </div>
        <LanguagePicker
          value={settings.uiLanguage as UiLanguage}
          onChange={(v) => {
            void (async () => {
              // Local write first, AWAITED before the relay: the host's echo
              // push applies through storage, and a still-in-flight local
              // write landing after it would clobber the applied value. The
              // lang_choose relay is the gesture -> lang_set path of
              // ADR-0032 decision 7 (the SW emits only when paired and the
              // live connection allows it; offline the choice stays local).
              await update("uiLanguage", v);
              await send({ type: "lang_choose", value: v });
            })();
          }}
        />
      </header>

      <Section title={t("options.section_kill")}>
        <KillSwitchPanel />
      </Section>

      <Section title={t("options.section_pairing")} id="pairing">
        <EnrollmentPanel />
      </Section>

      <Section title={t("options.section_sites")}>
        {/* the page's one boxed hero: where the browser is actually reachable.
            Placed directly after kill + pairing - it is the decision that
            scopes everything below. */}
        <div className="overflow-hidden rounded-lg border border-edge-strong bg-surface-2">
          <SiteList />
          <div className="border-t border-edge px-3.5">
            <SettingRow
              title={t("settings.allow_all_title")}
              desc={t("settings.allow_all_desc")}
              warn={t("settings.allow_all_warn")}
              checked={effectiveAllowAll}
              dangerOn="checked"
              onChange={(v) => void toggleAllowAll(v)}
            />
          </div>
        </div>
        <p className="consequence mt-2">{t("settings.sites_consequence")}</p>
      </Section>

      <Section title={t("options.section_security")}>
        {/* The ADR-0032 pointer where the 15 policy toggles used to be: the
            security policy is host-owned - edited in the app, signed by the
            paired key, enforced here - so this page shows where it lives
            instead of pretending to control it. */}
        <div className="py-1">
          <div className="text-[13px] font-medium">{t("settings.policy_managed_title")}</div>
          <p className="consequence mt-1">{t("settings.policy_managed_desc")}</p>
        </div>
      </Section>

      <Section title={t("options.section_clients")}>
        <TrustedClientsPanel />
      </Section>

      <Section title={t("options.section_tabs")}>
        <SettingRow
          title={t("settings.group_tabs_title")}
          desc={t("settings.group_tabs_desc")}
          more={t("settings.group_tabs_more")}
          checked={settings.groupTabs}
          dangerOn="unchecked"
          onChange={(v) => void update("groupTabs", v)}
        />
      </Section>

      <Section title={t("options.section_audit")}>
        <AuditPanel />
      </Section>

      {/* the exact host id this browser trusts, and the protocol it speaks */}
      <footer className="mt-10 border-t border-edge pt-3 font-mono text-[11px] text-text-3">
        {NATIVE_HOST_ID} - protocol {BRIDGE_PROTOCOL_VERSION}
      </footer>
    </div>
  );
}
