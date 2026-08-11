// JetBrains Mono is the mono face for identity material (fingerprints,
// origins, host ids); bundled locally - no remote fonts. Latin subsets of
// exactly the weights the design uses.
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/App";
import { syncHtmlLang } from "@/lib/i18n";
import { initLanguageSync } from "@/lib/lang-sync";
import "@/styles.css";

// index.html hardcodes lang="en"; the runtime locale (zh_CN/zh_TW) must
// override it or screen readers announce Chinese text with an English voice.
syncHtmlLang();

// Shared language (ADR-0032 decision 7): one startup pull of the host's
// lang_current, then follow lang-epoch notices. Apply-only - the sole
// lang_set emitter is the LanguagePicker's click handler.
initLanguageSync();

const rootElement = document.getElementById("root");
if (rootElement === null) throw new Error("missing #root");
createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
