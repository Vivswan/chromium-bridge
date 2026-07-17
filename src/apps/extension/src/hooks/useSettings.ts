import { type Settings, salvageSettings } from "@chromium-bridge/shared";
import { useEffect, useRef, useState } from "react";
import { browser } from "wxt/browser";
import { DEFAULTS } from "@/lib/shared/settings";

async function readAll(): Promise<Settings> {
  const bag = await browser.storage.local.get(Object.keys(DEFAULTS));
  return salvageSettings(bag);
}

/** Live settings, backed by storage.onChanged (event-driven; no polling). A
 * write goes straight to storage; the change event refreshes every open view.
 * The confirmation window and options page can therefore never show a stale
 * value. */
export function useSettings(): {
  settings: Settings;
  update: <K extends keyof Settings>(key: K, value: Settings[K]) => Promise<void>;
} {
  const [settings, setSettings] = useState<Settings>(DEFAULTS);
  // Monotonic guard: reads (initial + every onChanged refresh) can resolve out
  // of order, and an older snapshot must never clobber a newer one - that
  // would silently roll back a security toggle. Only the newest read commits.
  const readSeq = useRef(0);

  useEffect(() => {
    let live = true;
    const refresh = () => {
      const seq = ++readSeq.current;
      void readAll().then((s) => {
        if (live && seq === readSeq.current) setSettings(s);
      });
    };
    refresh();
    const onChange = (_changes: unknown, area: string) => {
      if (area === "local") refresh();
    };
    browser.storage.onChanged.addListener(onChange);
    return () => {
      live = false;
      browser.storage.onChanged.removeListener(onChange);
    };
  }, []);

  const update = async <K extends keyof Settings>(key: K, value: Settings[K]) => {
    // Bump the read sequence so any in-flight (older) read cannot land after
    // this optimistic write; the onChanged refresh that follows re-reads the
    // committed truth under a fresh sequence.
    readSeq.current += 1;
    setSettings((prev) => ({ ...prev, [key]: value }));
    await browser.storage.local.set({ [key]: value });
  };

  return { settings, update };
}
