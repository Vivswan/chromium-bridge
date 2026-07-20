#!/usr/bin/env bun

// Build and sign the desktop bundle end to end (ADR-0026, extended by the
// Phase 9 app, ADR-0029). One command: `moon run bundle-app`.
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
//      fixed icon positions, volume icon) by writing the mounted volume's
//      .DS_Store deterministically (scripts/dmg-dsstore.ts) - no Finder, no
//      AppleScript - so it styles identically on a headless CI runner and
//      locally.
//
// macOS-only by design: the entitlement chain is the thing under test.

import {
  copyFileSync,
  cpSync,
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
  console.error("error: scripts/desktop-bundle.ts is macOS-only (it exercises the signing chain)");
  process.exit(1);
}

const wantDmg = process.argv.includes("--dmg");

// --plain-dmg used to skip the Finder-based styling; the styling is now
// deterministic and Finder-free (see below), so there is no unstyled path to
// fall back to. Reject it explicitly rather than silently building no dmg.
if (process.argv.includes("--plain-dmg")) {
  console.error(
    "error: --plain-dmg was removed; the styled dmg is now built without Finder. Use --dmg.",
  );
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

// Best-effort detach so a partial run never leaves a read-write image
// attached: a plain detach first, then -force if something transient (a
// stray mds indexer, say) still holds the volume.
function detach(target: string): boolean {
  return attempt(["hdiutil", "detach", target]) || attempt(["hdiutil", "detach", "-force", target]);
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

// tauri build writes its bundle under the cargo target dir; that tree is a
// build intermediate here - the signed deliverable is copied to build/app below.
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
// loadable extension (the directory with manifest.json) at
// build/extension/chrome-mv3.
const extensionDist = resolve(root, "build/extension/chrome-mv3");
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

// The deliverable lives in build/app/ (the unified build-output folder);
// target/ stays a compiler cache. `ditto` preserves the signature, and the
// verification below runs on the COPY - the artifact users actually launch.
const appDeliverable = resolve(root, "build/app/Chromium Bridge.app");
rmSync(appDeliverable, { recursive: true, force: true });
mkdirSync(resolve(root, "build/app"), { recursive: true });
run(["ditto", app, appDeliverable]);

run(["bun", resolve(root, "scripts/check-desktop-signing.ts")]);

// --dmg: wrap the verified .app in a distributable disk image. `ditto`
// preserves the signature (cpSync would not keep every attribute), the
// /Applications symlink gives the standard drag-to-install layout, and the
// image itself is codesigned. The copy inside the mounted image is then
// re-verified so "check-desktop-signing passed" holds for the artifact that
// ships, not just the build-tree .app.
//
// The install window is branded: the stage carries the rendered background
// (assets/dmg/background.svg -> hidpi TIFF) and the volume icon, and the
// mounted volume's .DS_Store (window size, icon positions, background) is
// written DETERMINISTICALLY by scripts/dmg-dsstore.ts - no Finder, no
// AppleScript - so the styled image is produced identically on a headless CI
// runner and locally. Styling is cosmetic, not a security gate, but it still
// fails loudly rather than shipping a half-styled image.
if (wantDmg) {
  const arch = process.arch === "arm64" ? "arm64" : process.arch;
  const dmgDir = resolve(root, "build/dmg");
  const stage = resolve(dmgDir, "stage");
  const mount = resolve(dmgDir, "mnt");
  const dmg = resolve(dmgDir, `chromium-bridge-app-${version}-macos-${arch}.dmg`);
  const volname = "Chromium Bridge";
  const appName = "Chromium Bridge.app";
  rmSync(dmgDir, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });
  run(["ditto", appDeliverable, resolve(stage, appName)]);
  symlinkSync("/Applications", resolve(stage, "Applications"));

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
  // Attach, and from hdiutil's output take both the /Volumes mount point (for
  // the styling steps, which need a filesystem path) and the whole-disk device
  // node like /dev/disk4 (for the detach). Detaching by device node is
  // unambiguous: if a same-named volume was already mounted, macOS gives this
  // image a suffixed /Volumes path, but the device node still names exactly the
  // image this run attached - never someone else's volume.
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
  const rows = attachOut.split("\n").map((line) => line.split("\t").map((field) => field.trim()));
  const mounted = rows
    .map((fields) => fields[fields.length - 1])
    .find((last) => last?.startsWith("/Volumes/"));
  const device = rows.map((fields) => fields[0]?.match(/^\/dev\/disk\d+/)?.[0]).find((d) => d);
  if (device === undefined) {
    // Should never happen (the device node is hdiutil's primary output); with
    // no handle on what we attached, refuse rather than risk detaching the
    // wrong disk.
    console.error("error: no device node in hdiutil attach output; detach manually");
    process.exit(1);
  }
  if (mounted === undefined) {
    // Attached but no mount point parsed: detach OUR device node best-effort so
    // the image is not left attached.
    detach(device);
    console.error("error: no mount point in hdiutil attach output");
    process.exit(1);
  }

  // Write the .DS_Store deterministically (window bounds, icon positions, the
  // background alias generated per build against THIS mount), then set
  // kHasCustomIcon so Finder uses .VolumeIcon.icns. Both must land while the
  // volume is mounted; on failure, detach before exiting so a partial run
  // never leaves the read-write image attached. `sync` flushes our writes to
  // the image before detach.
  let ok = attempt(["bun", resolve(root, "scripts/dmg-dsstore.ts"), mounted, volname, appName]);
  ok = ok && attempt(["SetFile", "-a", "C", mounted]);
  Bun.spawnSync(["sync"], { stdout: "inherit", stderr: "inherit" });

  const detached = detach(device);
  if (!ok || !detached) {
    console.error("error: DMG window styling failed");
    process.exit(1);
  }

  run(["hdiutil", "convert", rw, "-format", "UDZO", "-imagekey", "zlib-level=9", "-ov", "-o", dmg]);
  rmSync(rw, { force: true });

  rmSync(stage, { recursive: true, force: true });
  run(["codesign", "--force", "--sign", identity, dmg]);
  run(["hdiutil", "attach", dmg, "-readonly", "-nobrowse", "-mountpoint", mount]);
  // Not run(): the image must be detached whether or not the check passes.
  const check = Bun.spawnSync(
    ["bun", resolve(root, "scripts/check-desktop-signing.ts"), resolve(mount, appName)],
    { cwd: root, stdout: "inherit", stderr: "inherit" },
  );
  run(["hdiutil", "detach", mount]);
  if (check.exitCode !== 0) {
    console.error("error: check-desktop-signing failed on the app inside the dmg");
    process.exit(check.exitCode ?? 1);
  }
  console.log(`dmg: ${dmg}`);
}
