import React from "react";
import ReactDOM from "react-dom/client";
import { initI18n, syncHtmlLang } from "@/lib/i18n";
import { initTheme } from "@/lib/theme";
import "@/assets/styles.css";
import { OptionsApp } from "./OptionsApp";

initTheme();
void initI18n().then(() => {
  syncHtmlLang();
  const root = document.getElementById("root");
  if (!root) throw new Error("missing #root");
  ReactDOM.createRoot(root).render(
    <React.StrictMode>
      <OptionsApp />
    </React.StrictMode>,
  );
});
