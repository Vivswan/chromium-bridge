#!/usr/bin/env bun

// Build and sign the desktop bundle end to end (ADR-0026, extended by the
// Phase 9 app, ADR-0029). One command: `just desktop-bundle`.
//
//   1. build the release host binary (the Secure Enclave toucher)
//   2. build the extension (bundled into the app for "Load unpacked")
//   3. `tauri build` (builds the UI + app, bundles, signs the .app)
//   4. wrap the host in a HELPER BUNDLE inside the app
//      (Contents/Helpers/chromium-bridge.app): macOS honors restricted
//      entitlements only on a bundle's main executable with an embedded
//      provisioning profile - a bare nested binary is SIGKILLed at exec.
//      The helper Info.plist is stamped with the workspace version here, so
//      it cannot go stale against Cargo.toml.
//   5. copy the extension dist into Contents/Resources/extension
//   6. embed the Mac Team provisioning profile (discovered from Xcode's
//      profile cache, or supplied via PROVISION_PROFILE_PATH in CI) in the
//      helper and the outer app
//   7. sign inside-out: the helper with the HOST's own entitlements
//      (entitlements/host.entitlements), then the outer app with its own
//      (entitlements/app.entitlements)
//   8. re-assert the final bundle with scripts/check-desktop-signing.ts,
//      which fails on entitlement drift, a get-task-allow appearance, or an
//      expired profile
//   9. with --dmg, wrap the verified .app in a signed UDZO disk image and
//      re-verify the copy inside the mounted image (the .dmg is what ships;
//      hdiutil runs AFTER the re-sign because tauri's own dmg target would
//      capture the .app before the helper bundle exists). The image gets the
//      branded install window (background from assets/dmg/background.svg,
//      fixed icon positions, volume icon) via Finder scripting on a
//      temporary read-write image; --plain-dmg skips the styling and ships
//      the bare drag-to-install layout (the fallback when Finder automation
//      is unavailable).
//
// macOS-only by design: the entitlement chain is the thing under test.

import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { cargoVersion } from "./lib.ts";
import {
  findUsableProfile,
  type ProvisioningProfile,
  profileProblems,
  provisioningUdid,
  readProvisioningProfile,
  xcodeProfileDir,
} from "./provisioning.ts";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const desktop = resolve(root, "src/apps/desktop");

// Team ID = the signing certificate's OU (see check-desktop-signing.ts).
const TEAM_ID = "3ZMH96L4V9";

if (process.platform !== "darwin") {
  console.error("error: desktop-bundle is macOS-only (it exercises the signing chain)");
  process.exit(1);
}

const wantDmg = process.argv.includes("--dmg") || process.argv.includes("--plain-dmg");
const plainDmg = process.argv.includes("--plain-dmg");

function run(cmd: string[], cwd: string = root): void {
  console.log(`+ ${cmd.join(" ")}`);
  const proc = Bun.spawnSync(cmd, { cwd, stdout: "inherit", stderr: "inherit" });
  if (proc.exitCode !== 0) {
    console.error(`error: ${cmd[0]} exited with ${proc.exitCode}`);
    process.exit(proc.exitCode ?? 1);
  }
}

// Like run(), but reports failure instead of exiting - for the styling steps
// between hdiutil attach and detach, where bailing out would leave the
// read-write image mounted.
function attempt(cmd: string[]): boolean {
  console.log(`+ ${cmd.join(" ")}`);
  try {
    const proc = Bun.spawnSync(cmd, { cwd: root, stdout: "inherit", stderr: "inherit" });
    return proc.exitCode === 0;
  } catch {
    console.error(`error: could not execute ${cmd[0]}`);
    return false;
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

// Find a live provisioning profile authorizing our full entitlement chain
// (fail-closed: identifier, team, keychain group, device, and expiry must
// all check out). Two sources:
//
//   - PROVISION_PROFILE_PATH (CI): an explicit profile file, decoded from a
//     repository secret. The this-device check is skipped - the runner is
//     never in a free-tier profile's device list - so the built app runs
//     only on Macs the supplied profile provisions (AMFI enforces that at
//     exec regardless of what we check here).
//   - default (local): the newest usable profile in Xcode's cache. Free-tier
//     profiles expire after 7 days; when none is usable, Xcode's automatic
//     signing mints a fresh one (open any Xcode project with this bundle id
//     and the team selected).
const envProfilePath = process.env.PROVISION_PROFILE_PATH;
let profile: ProvisioningProfile;
if (envProfilePath !== undefined && envProfilePath !== "") {
  const parsed = readProvisioningProfile(envProfilePath);
  if (parsed === undefined) {
    console.error(`error: PROVISION_PROFILE_PATH could not be decoded (${envProfilePath})`);
    process.exit(1);
  }
  const problems = profileProblems(parsed, {
    appIdentifier,
    teamId: TEAM_ID,
    keychainGroup: appIdentifier,
    deviceUdid: undefined,
  });
  if (problems.length > 0) {
    console.error(`error: PROVISION_PROFILE_PATH is not usable: ${problems.join("; ")}`);
    process.exit(1);
  }
  console.log(
    "PROVISION_PROFILE_PATH set: this-device check skipped; the app will run only on Macs this profile provisions",
  );
  profile = parsed;
} else {
  const udid = provisioningUdid();
  if (udid === undefined) {
    console.error("error: could not determine this Mac's provisioning UDID (system_profiler)");
    process.exit(1);
  }
  const found = findUsableProfile({
    appIdentifier,
    teamId: TEAM_ID,
    keychainGroup: appIdentifier,
    deviceUdid: udid,
  });
  if (found === undefined) {
    console.error(
      `error: no usable provisioning profile for ${appIdentifier} in\n  ${xcodeProfileDir()}\n` +
        "free-tier profiles expire after 7 days; mint a fresh one by opening an\n" +
        "Xcode project with this bundle id and automatic signing (Team " +
        `${TEAM_ID}), then re-run.`,
    );
    process.exit(1);
  }
  profile = found;
}
console.log(`provisioning profile: ${profile.path} (expires ${profile.expires.toISOString()})`);

run(["bun", resolve(root, "scripts/gen-icons.ts"), "desktop"]);
run(["cargo", "build", "--release", "-p", "chromium-bridge"]);
run(["bun", "run", "--cwd", "src/apps/extension", "build"]);
run(["bunx", "tauri", "build"], desktop);

const app = resolve(root, "target/release/bundle/macos/Chromium Bridge.app");
const helper = resolve(app, "Contents/Helpers/chromium-bridge.app");
mkdirSync(resolve(helper, "Contents/MacOS"), { recursive: true });

// Stamp the helper Info.plist with the workspace version (Cargo.toml is the
// single source; the checked-in plist's placeholder values must not ship).
const version = cargoVersion();
const plistSource = readFileSync(resolve(desktop, "host-bundle/Info.plist"), "utf8");
const plist = plistSource.replace(
  /(<key>CFBundle(?:ShortVersionString|Version)<\/key>\s*<string>)[^<]+(<\/string>)/g,
  `$1${version}$2`,
);
if (!plist.includes(`<string>${version}</string>`)) {
  console.error("error: could not stamp the version into host-bundle/Info.plist");
  process.exit(1);
}
writeFileSync(resolve(helper, "Contents/Info.plist"), plist);
copyFileSync(
  resolve(root, "target/release/chromium-bridge"),
  resolve(helper, "Contents/MacOS/chromium-bridge"),
);

// Bundle the unpacked extension for the app's "Load unpacked" guidance
// (Resources are sealed by the outer signature below). WXT emits the
// loadable extension (the directory with manifest.json) at dist/chrome-mv3.
const extensionDist = resolve(root, "src/apps/extension/dist/chrome-mv3");
const extensionDest = resolve(app, "Contents/Resources/extension");
rmSync(extensionDest, { recursive: true, force: true });
cpSync(extensionDist, extensionDest, { recursive: true });

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

// --dmg: wrap the verified .app in a distributable disk image. `ditto`
// preserves the signature (cpSync would not keep every attribute), the
// /Applications symlink gives the standard drag-to-install layout, and the
// image itself is codesigned. The copy inside the mounted image is then
// re-verified so "check-desktop-signing passed" holds for the artifact that
// ships, not just the build-tree .app.
//
// By default the install window is branded: the stage carries the rendered
// background (assets/dmg/background.svg -> hidpi TIFF) and the volume icon,
// and Finder scripting on a temporary read-write image writes the .DS_Store
// (window size, icon positions) before conversion to the final compressed
// UDZO image. Styling is cosmetic, not a security gate, but it still fails
// loudly rather than shipping a half-styled image; --plain-dmg is the
// explicit fallback when Finder automation is unavailable (e.g. a CI runner
// without an automation-capable UI session).
if (wantDmg) {
  const arch = process.arch === "arm64" ? "arm64" : process.arch;
  const dmgDir = resolve(root, "target/release/bundle/dmg");
  const stage = resolve(dmgDir, "stage");
  const mount = resolve(dmgDir, "mnt");
  const dmg = resolve(dmgDir, `chromium-bridge-app-${version}-macos-${arch}.dmg`);
  const volname = "Chromium Bridge";
  // Finder is scripted against the volume by NAME, so an already-mounted
  // volume with the same name would make it style the wrong disk. Checked
  // before the rmSync: if a previous run failed to detach, deleting dmgDir
  // here would pull the still-mounted rw.dmg out from under the mount.
  const volume = `/Volumes/${volname}`;
  if (!plainDmg && existsSync(volume)) {
    console.error(`error: a volume is already mounted at ${volume}; detach it and re-run`);
    process.exit(1);
  }
  rmSync(dmgDir, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });
  run(["ditto", app, resolve(stage, "Chromium Bridge.app")]);
  symlinkSync("/Applications", resolve(stage, "Applications"));

  if (plainDmg) {
    run([
      "hdiutil",
      "create",
      "-volname",
      volname,
      "-srcfolder",
      stage,
      "-format",
      "UDZO",
      "-ov",
      dmg,
    ]);
  } else {
    // Window dressing travels inside the image (dotfiles stay hidden in
    // Finder). The volume icon reuses the app's own icns; the background
    // TIFF is rendered from the committed SVG at build time.
    mkdirSync(resolve(stage, ".background"));
    run([
      "bun",
      resolve(root, "scripts/gen-dmg-background.ts"),
      resolve(stage, ".background/background.tiff"),
    ]);
    copyFileSync(resolve(desktop, "icons/icon.icns"), resolve(stage, ".VolumeIcon.icns"));

    const rw = resolve(dmgDir, "rw.dmg");
    run([
      "hdiutil",
      "create",
      "-volname",
      volname,
      "-srcfolder",
      stage,
      "-fs",
      "HFS+",
      "-format",
      "UDRW",
      "-ov",
      rw,
    ]);
    // Attach and take the actual mount point from hdiutil's output (the
    // last tab-separated field of the volume line), so every later step -
    // and above all the detach - targets the exact mount this run created.
    console.log(`+ hdiutil attach ${rw} -nobrowse -noautoopen`);
    const attach = Bun.spawnSync(["hdiutil", "attach", rw, "-nobrowse", "-noautoopen"], {
      cwd: root,
      stdout: "pipe",
      stderr: "inherit",
    });
    const attachOut = attach.stdout.toString();
    process.stdout.write(attachOut);
    if (attach.exitCode !== 0) {
      console.error(`error: hdiutil attach exited with ${attach.exitCode}`);
      process.exit(attach.exitCode ?? 1);
    }
    const mounted = attachOut
      .split("\n")
      .map((line) => line.split("\t").map((field) => field.trim()))
      .map((fields) => fields[fields.length - 1])
      .find((last) => last?.startsWith("/Volumes/"));
    if (mounted === undefined) {
      attempt(["hdiutil", "detach", volume]);
      console.error("error: no mount point in hdiutil attach output");
      process.exit(1);
    }

    // Icon coordinates and window size are a layout contract with
    // assets/dmg/background.svg (app at 165,190; Applications at 495,190;
    // 660x400 content area) - keep them in sync.
    const style = `
tell application "Finder"
  tell disk "${volname}"
    open
    delay 1
    set current view of container window to icon view
    set toolbar visible of container window to false
    set statusbar visible of container window to false
    set the bounds of container window to {200, 120, 860, 520}
    set viewOptions to the icon view options of container window
    set arrangement of viewOptions to not arranged
    set icon size of viewOptions to 128
    set text size of viewOptions to 12
    set background picture of viewOptions to file ".background:background.tiff"
    set position of item "Chromium Bridge.app" of container window to {165, 190}
    set position of item "Applications" of container window to {495, 190}
    close
    open
    update without registering applications
    delay 1
    close
  end tell
end tell`;

    // Finder automation is the flaky link (slow first launch, occasional
    // AppleEvent timeouts on CI), so it gets retries.
    let styled = false;
    for (let i = 1; i <= 3 && !styled; i++) {
      if (i > 1) {
        console.error(`finder styling attempt ${i - 1} failed; retrying`);
        Bun.sleepSync(2000);
      }
      styled = attempt(["osascript", "-e", style]);
    }

    // kHasCustomIcon on the volume root makes Finder use .VolumeIcon.icns.
    // SetFile comes with the Xcode command-line tools; if it is absent,
    // attempt() fails the build loudly below.
    let ok = styled && attempt(["SetFile", "-a", "C", mounted]);

    // Finder writes the .DS_Store asynchronously; give it a moment to land
    // before the volume is detached.
    if (ok) {
      let flushed = existsSync(resolve(mounted, ".DS_Store"));
      for (let i = 0; i < 20 && !flushed; i++) {
        Bun.sleepSync(500);
        flushed = existsSync(resolve(mounted, ".DS_Store"));
      }
      if (!flushed) {
        console.error("error: Finder never wrote the volume .DS_Store");
        ok = false;
      }
      Bun.spawnSync(["sync"], { stdout: "inherit", stderr: "inherit" });
    }

    let detached = false;
    for (let i = 0; i < 6 && !detached; i++) {
      if (i > 0) Bun.sleepSync(1000);
      detached = attempt(["hdiutil", "detach", mounted]);
    }
    if (!ok || !detached) {
      console.error(
        "error: DMG window styling failed; fix Finder automation or re-run with --plain-dmg",
      );
      process.exit(1);
    }

    run([
      "hdiutil",
      "convert",
      rw,
      "-format",
      "UDZO",
      "-imagekey",
      "zlib-level=9",
      "-ov",
      "-o",
      dmg,
    ]);
    rmSync(rw, { force: true });
  }

  rmSync(stage, { recursive: true, force: true });
  run(["codesign", "--force", "--sign", identity, dmg]);
  run(["hdiutil", "attach", dmg, "-readonly", "-nobrowse", "-mountpoint", mount]);
  // Not run(): the image must be detached whether or not the check passes.
  const check = Bun.spawnSync(
    [
      "bun",
      resolve(root, "scripts/check-desktop-signing.ts"),
      resolve(mount, "Chromium Bridge.app"),
    ],
    { cwd: root, stdout: "inherit", stderr: "inherit" },
  );
  run(["hdiutil", "detach", mount]);
  if (check.exitCode !== 0) {
    console.error("error: check-desktop-signing failed on the app inside the dmg");
    process.exit(check.exitCode ?? 1);
  }
  console.log(`dmg: ${dmg}`);
}
