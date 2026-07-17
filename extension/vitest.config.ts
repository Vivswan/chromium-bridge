import { defineConfig } from "vitest/config";
import { WxtVitest } from "wxt/testing";

export default defineConfig({
  plugins: [WxtVitest({ browser: "chrome", manifestVersion: 3 })],
  test: {
    environment: "happy-dom",
    globals: true,
    exclude: ["**/node_modules/**", "dist/**", ".wxt/**"],
    setupFiles: ["./tests/setup.ts"],
  },
});
