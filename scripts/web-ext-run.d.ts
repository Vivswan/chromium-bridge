// Minimal ambient types for web-ext-run (ships no .d.ts). Covers only the
// surface scripts/dev-browser.ts uses to own the dev browser lifecycle.
declare module "web-ext-run" {
  interface ChromiumRunConfig {
    target: "chromium";
    sourceDir: string;
    startUrl?: string[];
    chromiumBinary?: string;
    chromiumProfile?: string;
    chromiumPref?: Record<string, unknown>;
    keepProfileChanges?: boolean;
    args?: string[];
    noReload?: boolean;
    noInput?: boolean;
  }
  interface RunOptions {
    shouldExitProgram?: boolean;
    // web-ext's injectable runner class (its dependency-injection seam). We
    // pass a wrapper so we hold the runner handle even if run() rejects after
    // spawning the browser.
    // biome-ignore lint/style/useNamingConvention: web-ext's option key is PascalCase (a class)
    MultiExtensionRunner?: new (params: {
      runners: unknown[];
    }) => unknown;
  }
  interface ExtensionRunner {
    registerCleanup(fn: () => void): void;
    exit(): Promise<void>;
    run(): Promise<void>;
    reloadAllExtensions(): Promise<unknown>;
  }
  const webExt: {
    cmd: {
      run(config: ChromiumRunConfig, options?: RunOptions): Promise<ExtensionRunner>;
    };
  };
  export default webExt;
}
