import { OP_NAMES } from "@chromium-bridge/shared";
import { useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { LanguagePicker } from "@/components/app/LanguagePicker";
import { Section, SettingRow } from "@/components/app/SettingRow";
import { Switch } from "@/components/ui/switch";
import { useI18n } from "@/hooks/useI18n";
import { useSettings } from "@/hooks/useSettings";
import type { UiLanguage } from "@/lib/i18n";
import { AuditPanel } from "./AuditPanel";
import { EnrollmentPanel } from "./EnrollmentPanel";
import { KillSwitchPanel } from "./KillSwitchPanel";
import { SiteList } from "./SiteList";
import { TrustedClientsPanel } from "./TrustedClientsPanel";

// The options page: security toggles, host pairing, tabs, execution mode,
// timeouts, tools, and the allowlist. Every write is event-driven (useSettings
// is backed by storage.onChanged), so there is no polling and no manual
// refresh; a change from any surface reflects here immediately.
//
// Control Tower: flat hairline-separated open sections; the sites list is the
// page's single boxed hero. Amber and red stay reserved for pending and
// kill/deny - consequences are neutral ink.
export function OptionsApp() {
  const { t } = useI18n();
  const { settings, update } = useSettings();
  const [allowAllHeld, setAllowAllHeld] = useState<boolean | null>(null);

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

  const num = (
    key: "confirmGraceMs" | "clickToastTimeoutMs" | "evalToastTimeoutMs" | "hostReverifyMs",
    label: string,
  ) => (
    <input
      type="number"
      min={0}
      aria-label={label}
      value={settings[key]}
      onChange={(e) => {
        const v = Number.parseInt(e.target.value, 10);
        if (!Number.isNaN(v)) void update(key, v);
      }}
      className="tnum w-28 rounded-md border border-edge-strong bg-surface-1 px-2.5 py-1.5 text-xs text-text-1"
    />
  );

  return (
    <div className="mx-auto max-w-[720px] px-6 pb-20 pt-8 text-sm">
      <header className="flex items-start justify-between gap-4 border-b border-edge pb-4">
        <div>
          <h1 className="m-0 text-base font-semibold tracking-tight">{t("options.title")}</h1>
          <div className="mt-0.5 text-xs text-text-3">{t("options.subtitle")}</div>
        </div>
        <LanguagePicker
          value={settings.uiLanguage as UiLanguage}
          onChange={(v) => void update("uiLanguage", v)}
        />
      </header>

      <Section title={t("options.section_kill")}>
        <KillSwitchPanel />
      </Section>

      <Section title={t("options.section_security")}>
        <SettingRow
          title={t("settings.require_enrollment_title")}
          desc={t("settings.require_enrollment_desc")}
          warn={t("settings.require_enrollment_warn")}
          checked={settings.requireEnrollment}
          dangerOn="unchecked"
          onChange={(v) => void update("requireEnrollment", v)}
        />
        <SettingRow
          title={t("settings.page_eval_title")}
          desc={t("settings.page_eval_desc")}
          checked={settings.pageEvalEnabled}
          dangerOn="unchecked"
          onChange={(v) => void update("pageEvalEnabled", v)}
        />
        <SettingRow
          title={t("settings.eval_mask_title")}
          desc={t("settings.eval_mask_desc")}
          warn={t("settings.eval_mask_warn")}
          checked={settings.evalMask}
          dangerOn="unchecked"
          onChange={(v) => void update("evalMask", v)}
        />
        <SettingRow
          title={t("settings.confirm_click_title")}
          desc={t("settings.confirm_click_desc")}
          warn={t("settings.confirm_click_warn")}
          checked={settings.confirmHighRiskClick}
          dangerOn="unchecked"
          onChange={(v) => void update("confirmHighRiskClick", v)}
        />
        <SettingRow
          title={t("settings.confirm_eval_title")}
          desc={t("settings.confirm_eval_desc")}
          warn={t("settings.confirm_eval_warn")}
          checked={settings.confirmPageEval}
          dangerOn="unchecked"
          onChange={(v) => void update("confirmPageEval", v)}
        />
        <SettingRow
          title={t("settings.touchid_confirm_title")}
          desc={t("settings.touchid_confirm_desc")}
          warn={t("settings.touchid_confirm_warn")}
          checked={settings.touchIdConfirm}
          dangerOn="unchecked"
          onChange={(v) => void update("touchIdConfirm", v)}
        />
        <SettingRow
          title={t("settings.confirm_tab_close_title")}
          desc={t("settings.confirm_tab_close_desc")}
          warn={t("settings.confirm_tab_close_warn")}
          checked={settings.confirmTabClose}
          dangerOn="unchecked"
          onChange={(v) => void update("confirmTabClose", v)}
        />
        <SettingRow
          title={t("settings.warn_precise_title")}
          desc={t("settings.warn_precise_desc")}
          checked={settings.warnPreciseSnapshot}
          dangerOn="unchecked"
          onChange={(v) => void update("warnPreciseSnapshot", v)}
        />
      </Section>

      <Section title={t("options.section_pairing")}>
        <EnrollmentPanel />
        <div className="border-t border-edge py-3">
          <div className="flex flex-wrap items-center gap-3">
            <span className="min-w-52 text-[13px] font-medium">{t("settings.reverify_label")}</span>
            {num("hostReverifyMs", t("settings.reverify_label"))}
            <span className="text-[11px] text-text-3">{t("settings.reverify_unit")}</span>
          </div>
          <div className="mt-1 text-xs text-text-3">{t("settings.reverify_desc")}</div>
        </div>
      </Section>

      <Section title={t("options.section_clients")}>
        <TrustedClientsPanel />
      </Section>

      <Section title={t("options.section_tabs")}>
        <SettingRow
          title={t("settings.group_tabs_title")}
          desc={t("settings.group_tabs_desc")}
          checked={settings.groupTabs}
          dangerOn="unchecked"
          onChange={(v) => void update("groupTabs", v)}
        />
      </Section>

      <Section title={t("options.section_execution")}>
        <SettingRow
          title={t("settings.cdp_mode_title")}
          desc={t("settings.cdp_mode_desc")}
          warn={t("settings.cdp_mode_warn")}
          checked={settings.cdpMode}
          dangerOn="checked"
          onChange={(v) => void update("cdpMode", v)}
        />
        <SettingRow
          title={t("settings.file_upload_title")}
          desc={t("settings.file_upload_desc")}
          warn={t("settings.file_upload_warn")}
          checked={settings.fileUploadEnabled}
          dangerOn="checked"
          onChange={(v) => void update("fileUploadEnabled", v)}
        />
        <SettingRow
          title={t("settings.handle_dialog_title")}
          desc={t("settings.handle_dialog_desc")}
          warn={t("settings.handle_dialog_warn")}
          checked={settings.handleDialogEnabled}
          dangerOn="checked"
          onChange={(v) => void update("handleDialogEnabled", v)}
        />
      </Section>

      <Section title={t("options.section_timeouts")}>
        {(
          [
            ["settings.grace_label", "settings.grace_unit", "confirmGraceMs"],
            ["settings.click_timeout_label", "settings.click_timeout_unit", "clickToastTimeoutMs"],
            ["settings.eval_timeout_label", "settings.eval_timeout_unit", "evalToastTimeoutMs"],
          ] as const
        ).map(([label, unit, key]) => (
          <div
            key={key}
            className="flex flex-wrap items-center gap-3 border-b border-edge py-2.5 last:border-b-0"
          >
            <span className="min-w-52 text-[13px] font-medium">{t(label)}</span>
            {num(key, t(label))}
            <span className="text-[11px] text-text-3">{t(unit)}</span>
          </div>
        ))}
      </Section>

      <Section title={t("options.section_tools")}>
        <p className="consequence mb-2 mt-0">{t("settings.tools_desc")}</p>
        <div className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
          {OP_NAMES.map((op) => {
            const enabled = !settings.disabledTools.includes(op);
            return (
              <div key={op} className="flex items-start gap-2.5 border-b border-edge py-2.5">
                <Switch
                  checked={enabled}
                  aria-label={op}
                  className="mt-0.5"
                  onCheckedChange={(on) => {
                    const next = on
                      ? settings.disabledTools.filter((o) => o !== op)
                      : [...settings.disabledTools, op];
                    void update("disabledTools", next);
                  }}
                />
                <div className="min-w-0">
                  <div className="font-mono text-xs font-semibold">{op}</div>
                  <div className="text-[11px] text-text-3">{t(`tools.${op}`)}</div>
                </div>
              </div>
            );
          })}
        </div>
      </Section>

      <Section title={t("options.section_sites")}>
        {/* the page's one boxed hero: where the browser is actually reachable */}
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

      <Section title={t("options.section_audit")}>
        <AuditPanel />
      </Section>
    </div>
  );
}
