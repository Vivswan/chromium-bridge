import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";

// The per-site allowlist editor: the row list of the options page's hero
// card (OptionsApp owns the card chrome). Event-driven: refreshes on
// storage.onChanged for the allowlist key, so an approval from the popup
// shows here at once.
export function SiteList() {
  const { t } = useI18n();
  const [list, setList] = useState<string[]>([]);
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");

  const refresh = useCallback(async () => {
    const resp = await send<{ list?: string[] }>({ type: "get_allowlist" });
    setList(resp?.list ?? []);
  }, []);

  useEffect(() => {
    void refresh();
    const onChange = (changes: Record<string, unknown>, area: string) => {
      if (area === "local" && "allowlist" in changes) void refresh();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => browser.storage.onChanged.removeListener(onChange);
  }, [refresh]);

  const add = async () => {
    const v = value.trim();
    if (!v) return;
    if (!/^https?:\/\/[^/]+\/?/.test(v)) {
      setNote(t("settings.add_site_format"));
      return;
    }
    let glob: string;
    try {
      const u = new URL(v);
      glob = `${u.protocol}//${u.host}/*`;
    } catch {
      setNote(t("settings.add_site_parse_failed"));
      return;
    }
    const resp = await send<{ ok?: boolean }>({ type: "add_allow", glob });
    if (resp?.ok) {
      setValue("");
      setNote("");
      void refresh();
    }
  };

  const remove = async (glob: string) => {
    await send({ type: "remove_allow", glob });
    void refresh();
  };

  return (
    <div>
      {list.length === 0 ? (
        <p className="m-0 px-3.5 py-3 text-xs text-text-3">{t("popup.no_sites")}</p>
      ) : (
        list.map((glob) => (
          <div
            key={glob}
            className="flex items-center gap-2.5 border-b border-edge px-3.5 py-2 last:border-b-0"
          >
            <code className="min-w-0 flex-1 truncate font-mono text-xs text-text-1">{glob}</code>
            <Button variant="ghost" className="px-2 py-1" onClick={() => void remove(glob)}>
              {t("common.remove")}
            </Button>
          </div>
        ))
      )}
      <div className="border-t border-edge px-3.5 py-2.5">
        <div className="flex gap-2">
          <input
            type="text"
            value={value}
            placeholder={t("settings.add_site_placeholder")}
            aria-label={t("settings.add_site_placeholder")}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void add();
            }}
            className="min-w-0 flex-1 rounded-md border border-edge-strong bg-surface-1 px-2.5 py-1.5 font-mono text-xs text-text-1 placeholder:text-text-4"
          />
          <Button onClick={() => void add()}>{t("common.add")}</Button>
        </div>
        {note && <p className="m-0 mt-1.5 text-xs font-semibold text-danger">{note}</p>}
      </div>
    </div>
  );
}
