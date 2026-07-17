import { TOOLS } from "@chromium-bridge/shared";
import { useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { LanguagePicker } from "@/components/app/LanguagePicker";
import { Section, SettingRow } from "@/components/app/SettingRow";
import { Switch } from "@/components/ui/switch";
import { useI18n } from "@/hooks/useI18n";
import { useSettings } from "@/hooks/useSettings";
import type { UiLanguage } from "@/lib/i18n";
import { EnrollmentPanel } from "./EnrollmentPanel";
import { SiteList } from "./SiteList";
import { TrustedClientsPanel } from "./TrustedClientsPanel";

// The options page: security toggles, host pairing, tabs, execution mode,
// timeouts, tools, and the allowlist. Every write is event-driven (useSettings
// is backed by storage.onChanged), so there is no polling and no manual
// refresh; a change from any surface reflects here immediately.
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
      className="w-28 rounded-lg border border-edge bg-surface px-2.5 py-1.5 text-sm focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand"
    />
  );

  return (
    <div className="mx-auto max-w-3xl px-6 pb-20 pt-10 text-sm leading-relaxed">
      <header className="mb-3 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("options.title")}</h1>
          <div className="mt-1 text-muted">{t("options.subtitle")}</div>
        </div>
        <LanguagePicker
          value={settings.uiLanguage as UiLanguage}
          onChange={(v) => void update("uiLanguage", v)}
        />
      </header>

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
        <div className="mt-3 rounded-xl border border-edge p-3.5">
          <div className="flex items-center gap-3">
            <span className="min-w-52 font-medium">{t("settings.reverify_label")}</span>
            {num("hostReverifyMs", t("settings.reverify_label"))}
            <span className="text-xs text-faint">{t("settings.reverify_unit")}</span>
          </div>
          <div className="mt-2 text-xs text-muted">{t("settings.reverify_desc")}</div>
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
        <div className="rounded-xl border border-edge px-3.5 py-1.5">
          {(
            [
              ["settings.grace_label", "settings.grace_unit", "confirmGraceMs"],
              [
                "settings.click_timeout_label",
                "settings.click_timeout_unit",
                "clickToastTimeoutMs",
              ],
              ["settings.eval_timeout_label", "settings.eval_timeout_unit", "evalToastTimeoutMs"],
            ] as const
          ).map(([label, unit, key]) => (
            <div
              key={key}
              className="flex flex-wrap items-center gap-3 border-b border-edge-soft py-2.5 last:border-b-0"
            >
              <span className="min-w-52 font-medium">{t(label)}</span>
              {num(key, t(label))}
              <span className="text-xs text-faint">{t(unit)}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title={t("options.section_tools")}>
        <div className="mb-3 text-muted">{t("settings.tools_desc")}</div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {TOOLS.map((tool) => {
            const enabled = !settings.disabledTools.includes(tool.op);
            return (
              <div
                key={tool.op}
                className="flex items-start gap-2.5 rounded-lg border border-edge p-3"
              >
                <Switch
                  checked={enabled}
                  aria-label={tool.op}
                  onCheckedChange={(on) => {
                    const next = on
                      ? settings.disabledTools.filter((o) => o !== tool.op)
                      : [...settings.disabledTools, tool.op];
                    void update("disabledTools", next);
                  }}
                />
                <div className="min-w-0">
                  <div className="font-mono text-xs font-semibold">{tool.op}</div>
                  <div className="text-[11px] text-faint">{t(`tools.${tool.op}`)}</div>
                </div>
              </div>
            );
          })}
        </div>
      </Section>

      <Section title={t("options.section_sites")}>
        <SettingRow
          title={t("settings.allow_all_title")}
          desc={t("settings.allow_all_desc")}
          warn={t("settings.allow_all_warn")}
          checked={effectiveAllowAll}
          dangerOn="checked"
          onChange={(v) => void toggleAllowAll(v)}
        />
        <SiteList />
      </Section>
    </div>
  );
}
