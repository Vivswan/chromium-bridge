import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The Tauri dev server (tauri.conf.json build.devUrl) expects this exact
// port; strictPort makes a collision fail loud instead of silently serving
// the app on a port the webview never loads.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    // WKWebView on the supported macOS floor; fine for the other platforms.
    target: "safari15",
    // Repo-root build/ folder (must agree with tauri.conf.json frontendDist);
    // outside the vite root, so emptyOutDir must be explicit.
    outDir: "../../../../build/desktop-ui",
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      "@": new URL("./src", import.meta.url).pathname,
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
  },
});
