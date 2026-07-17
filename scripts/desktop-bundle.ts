#!/usr/bin/env bun

// Build and sign the desktop bundle end to end (Phase 6 signing spike,
// ADR-0026). One command: `just desktop-bundle`.
//
//   1. build the release host binary (the Secure Enclave toucher)
//   2. `tauri build` (builds the app, bundles, signs the .app)
//   3. wrap the host in a HELPER BUNDLE inside the app
//      (Contents/Helpers/chromium-bridge.app): macOS honors restricted
//      entitlements only on a bundle's main executable with an embedded
//      provisioning profile - a bare nested binary is SIGKILLed at exec
//   4. embed the Mac Team provisioning profile (discovered from Xcode's
//      profile cache) in the helper and the outer app
//   5. sign inside-out: the helper with the HOST's own entitlements
//      (entitlements/host.entitlements), then the outer app with its own
//      (entitlements/app.entitlements)
//   6. re-assert the final bundle with scripts/check-desktop-signing.ts,
//      which fails on entitlement drift, a get-task-allow appearance, or an
//      expired profile
//
// macOS-only by design: the entitlement chain is the thing under test.

import { copyFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { findUsableProfile, provisioningUdid, xcodeProfileDir } from "./provisioning.ts";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const desktop = resolve(root, "src/apps/desktop");

// Team ID = the signing certificate's OU (see check-desktop-signing.ts).
const TEAM_ID = "3ZMH96L4V9";

if (process.platform !== "darwin") {
  console.error("error: desktop-bundle is macOS-only (it exercises the signing chain)");
  process.exit(1);
}

function run(cmd: string[], cwd: string = root): void {
  console.log(`+ ${cmd.join(" ")}`);
  const proc = Bun.spawnSync(cmd, { cwd, stdout: "inherit", stderr: "inherit" });
  if (proc.exitCode !== 0) {
    console.error(`error: ${cmd[0]} exited with ${proc.exitCode}`);
    process.exit(proc.exitCode ?? 1);
  }
}

// The signing identity and bundle id come from tauri.conf.json (single
// source; the bundler reads the same fields for the .app signature).
const tauriConf = JSON.parse(await Bun.file(resolve(desktop, "tauri.conf.json")).text()) as {
  identifier?: unknown;
  bundle?: { macOS?: { signingIdentity?: unknown } };
};
const identity = tauriConf.bundle?.macOS?.signingIdentity;
const bundleId = tauriConf.identifier;
if (typeof identity !== "string" || typeof bundleId !== "string") {
  console.error("error: tauri.conf.json is missing identifier or bundle.macOS.signingIdentity");
  process.exit(1);
}
const appIdentifier = `${TEAM_ID}.${bundleId}`;

// Find a live provisioning profile authorizing our full entitlement chain on
// this machine (fail-closed: identifier, team, keychain group, device, and
// expiry must all check out). Free-tier profiles expire after 7 days; when
// none is usable, Xcode's automatic signing mints a fresh one (open any
// Xcode project with this bundle id and the team selected).
const udid = provisioningUdid();
if (udid === undefined) {
  console.error("error: could not determine this Mac's provisioning UDID (system_profiler)");
  process.exit(1);
}
const profile = findUsableProfile({
  appIdentifier,
  teamId: TEAM_ID,
  keychainGroup: appIdentifier,
  deviceUdid: udid,
});
if (profile === undefined) {
  console.error(
    `error: no usable provisioning profile for ${appIdentifier} in\n  ${xcodeProfileDir()}\n` +
      "free-tier profiles expire after 7 days; mint a fresh one by opening an\n" +
      "Xcode project with this bundle id and automatic signing (Team " +
      `${TEAM_ID}), then re-run.`,
  );
  process.exit(1);
}
console.log(`provisioning profile: ${profile.path} (expires ${profile.expires.toISOString()})`);

run(["cargo", "build", "--release", "-p", "chromium-bridge"]);
run(["bunx", "tauri", "build"], desktop);

const app = resolve(root, "target/release/bundle/macos/Chromium Bridge.app");
const helper = resolve(app, "Contents/Helpers/chromium-bridge.app");
mkdirSync(resolve(helper, "Contents/MacOS"), { recursive: true });
copyFileSync(resolve(desktop, "host-bundle/Info.plist"), resolve(helper, "Contents/Info.plist"));
copyFileSync(
  resolve(root, "target/release/chromium-bridge"),
  resolve(helper, "Contents/MacOS/chromium-bridge"),
);
copyFileSync(profile.path, resolve(helper, "Contents/embedded.provisionprofile"));
copyFileSync(profile.path, resolve(app, "Contents/embedded.provisionprofile"));

// Inside-out: the helper first (with the HOST's entitlements), then the
// outer app to re-seal it over the new nested content.
run([
  "codesign",
  "--force",
  "--options",
  "runtime",
  "--identifier",
  bundleId,
  "--entitlements",
  resolve(desktop, "entitlements/host.entitlements"),
  "--sign",
  identity,
  helper,
]);
run([
  "codesign",
  "--force",
  "--options",
  "runtime",
  "--entitlements",
  resolve(desktop, "entitlements/app.entitlements"),
  "--sign",
  identity,
  app,
]);

run(["bun", resolve(root, "scripts/check-desktop-signing.ts")]);
