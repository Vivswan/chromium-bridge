// JetBrains Mono is the mono face for identity material (fingerprints,
// origins, host ids); bundled locally - no remote fonts. Latin subsets of
// exactly the weights the design uses.
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/App";
import "@/styles.css";

const rootElement = document.getElementById("root");
if (rootElement === null) throw new Error("missing #root");
createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
