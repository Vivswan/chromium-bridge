import { useCallback, useEffect, useState } from "react";
import { browser } from "wxt/browser";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/hooks/useI18n";
import { send } from "@/lib/messages";

// The per-site allowlist editor. Event-driven: refreshes on storage.onChanged
// for the allowlist key, so an approval from the popup shows here at once.
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
      <div className="mb-3 mt-2 flex gap-2">
        <input
          type="text"
          value={value}
          placeholder={t("settings.add_site_placeholder")}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void add();
          }}
          className="flex-1 rounded-lg border border-edge bg-surface px-3 py-2 font-mono text-sm focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand"
        />
        <Button variant="primary" onClick={() => void add()}>
          {t("common.add")}
        </Button>
      </div>
      {note && <div className="mb-2 text-xs text-danger-strong">{note}</div>}
      {list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-edge p-4 text-center text-xs text-faint">
          {t("popup.no_sites")}
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-edge">
          {list.map((glob) => (
            <div
              key={glob}
              className="flex items-center justify-between border-b border-edge-soft px-3 py-2.5 last:border-b-0"
            >
              <code className="font-mono text-xs">{glob}</code>
              <Button variant="ghost" className="px-2.5 py-1" onClick={() => void remove(glob)}>
                {t("common.remove")}
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
