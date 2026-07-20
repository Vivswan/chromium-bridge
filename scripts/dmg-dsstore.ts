#!/usr/bin/env bun

// Write a mounted DMG volume's .DS_Store deterministically, so the branded
// install window (background image, icon positions, window size) is produced
// with no Finder and no AppleScript - the same styled layout on a headless CI
// runner and on a developer's Mac. This replaces the old approach of scripting
// the live Finder over AppleEvents (retry loops, a flush poll, a --plain-dmg
// escape hatch); see scripts/desktop-bundle.ts.
//
//   bun scripts/dmg-dsstore.ts <mountPoint> <volumeName> <appBundleName>
//
// This is the appdmg toolchain (ds-store + macos-alias), the widely used
// standard for headless DMG styling, but driven through those packages'
// PURE-JS code paths only:
//
//   - ds-store's .DS_Store writer and its bwsp/icvp/Iloc/vSrn record encoders
//     (ds-store/lib/*), reached directly because ds-store's public Helper
//     hard-codes a call to macos-alias's NATIVE create(), and that native
//     addon cannot load under bun (it is a node-gyp/nan binding built against
//     a different runtime ABI). The lib/ modules take no macos-alias
//     dependency, so using them sidesteps the addon entirely.
//   - macos-alias's pure-JS alias serializer (macos-alias/lib/encode). The
//     one thing its native code did was read the HFS+ volume name; we already
//     know it (we created the volume), so createAlias() below supplies it and
//     assembles the rest in JS, faithfully porting macos-alias/lib/create.js.
//
// macos-alias still ships that native addon, and bun compiles it at install
// time on macOS (where a C toolchain is a given - this repo also builds Rust
// and signs with Xcode); it is os-gated to darwin, so non-macOS installs skip
// it, and either way we never load it. Nothing here requires the addon.
//
// The background alias is generated PER BUILD against the MOUNTED volume: a
// Mac OS alias is path- and inode-specific (it embeds the target/parent/volume
// inodes and ctimes of this exact mount), so no prebuilt .DS_Store or alias is
// committed.

import { statSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, resolve } from "node:path";

import { die } from "./lib.ts";

const require = createRequire(import.meta.url);

// Layout contract with assets/dmg/background.svg (keep in sync): app icon
// centered at (165, 190), /Applications at (495, 190), icon size 128, window
// content area 660x400. The window frame height is the content height + 22
// (the title bar), so the 660x400 background fills the content area exactly.
const ICON_SIZE = 128;
const WINDOW = { x: 200, y: 120, width: 660, height: 400 + 22 };
const APP_POS = { x: 165, y: 190 };
const APPLICATIONS_POS = { x: 495, y: 190 };
const BACKGROUND_REL = ".background/background.tiff";

function utf16be(str: string): Buffer {
  const b = Buffer.from(str, "ucs2");
  for (let i = 0; i < b.length; i += 2) {
    const a = b[i] as number;
    b[i] = b[i + 1] as number;
    b[i + 1] = a;
  }
  return b;
}

// Pure-JS port of macos-alias/lib/create.js. The upstream create() calls a
// native addon for exactly one value - the HFS+ volume name - which we pass
// in (`volumeName`) because we created the volume. Everything else is fs
// metadata plus macos-alias's own pure-JS `encode`.
function createAlias(targetPath: string, volumeName: string): Buffer {
  const encode = require("macos-alias/lib/encode") as (info: unknown) => Buffer;

  const parentPath = resolve(targetPath, "..");
  const targetStat = statSync(targetPath);
  const parentStat = statSync(parentPath);

  // Walk up to the volume root: stop when the device number changes (crossing
  // the mount point) or the inode stops changing (the filesystem root).
  let volumePath = targetPath;
  let lastDev = targetStat.dev;
  let lastIno = targetStat.ino;
  let lastPath = targetPath;
  for (;;) {
    const pp = resolve(lastPath, "..");
    const ps = statSync(pp);
    if (ps.dev !== lastDev || ps.ino === lastIno) {
      volumePath = lastPath;
      break;
    }
    lastDev = ps.dev;
    lastIno = ps.ino;
    lastPath = pp;
  }
  const volumeStat = statSync(volumePath);

  if (!targetStat.isFile() && !targetStat.isDirectory()) {
    die(`alias target is neither file nor directory: ${targetPath}`);
  }
  if (targetPath.slice(0, volumePath.length) !== volumePath) {
    die(`alias target ${targetPath} is not under its volume ${volumePath}`);
  }

  const extra: { type: number; length: number; data: Buffer }[] = [];
  const push = (type: number, data: Buffer) => extra.push({ type, length: data.length, data });

  // type 0: parent directory name (utf8)
  push(0, Buffer.from(basename(parentPath), "utf8"));
  // type 1: parent directory inode
  const parentId = Buffer.alloc(4);
  parentId.writeUInt32BE(parentStat.ino, 0);
  push(1, parentId);
  // type 14: target filename (utf16be, length-prefixed)
  const targetName = basename(targetPath);
  const t14 = Buffer.alloc(2 + targetName.length * 2);
  t14.writeUInt16BE(targetName.length, 0);
  utf16be(targetName).copy(t14, 2);
  push(14, t14);
  // type 15: volume name (utf16be, length-prefixed)
  const t15 = Buffer.alloc(2 + volumeName.length * 2);
  t15.writeUInt16BE(volumeName.length, 0);
  utf16be(volumeName).copy(t15, 2);
  push(15, t15);
  // type 18: volume-relative path to the target (utf8)
  push(18, Buffer.from(targetPath.slice(volumePath.length), "utf8"));
  // type 19: absolute volume path (utf8)
  push(19, Buffer.from(volumePath, "utf8"));

  return encode({
    version: 2,
    target: {
      id: targetStat.ino,
      type: targetStat.isDirectory() ? "directory" : "file",
      filename: targetName,
      created: targetStat.ctime,
    },
    parent: { id: parentStat.ino, name: basename(parentPath) },
    volume: {
      name: volumeName,
      created: volumeStat.ctime,
      signature: "H+",
      type: volumePath === "/" ? "local" : "other",
    },
    extra,
  });
}

const mount = process.argv[2];
const volname = process.argv[3];
const appBundleName = process.argv[4];
if (
  mount === undefined ||
  mount === "" ||
  volname === undefined ||
  volname === "" ||
  appBundleName === undefined ||
  appBundleName === ""
) {
  die("usage: bun scripts/dmg-dsstore.ts <mountPoint> <volumeName> <appBundleName>");
}
if (process.platform !== "darwin") {
  die("dmg-dsstore is macOS-only (it styles a mounted HFS+ DMG volume)");
}

// ds-store's .DS_Store file writer and record encoders, reached directly (see
// the header): the public Helper would pull in the native addon.
type DsFile = { push(entry: unknown): void; write(path: string, cb: (err?: Error) => void): void };
const DsStoreFile = require("ds-store/lib/ds-store") as new () => DsFile;
const Entry = require("ds-store/lib/entry") as {
  construct(filename: string, structureId: string, opts: Record<string, unknown>): unknown;
};

const rawAlias = createAlias(resolve(mount, BACKGROUND_REL), volname);
const file = new DsStoreFile();
file.push(Entry.construct(".", "vSrn", { value: 1 }));
file.push(Entry.construct(appBundleName, "Iloc", APP_POS));
file.push(Entry.construct("Applications", "Iloc", APPLICATIONS_POS));
file.push(Entry.construct(".", "bwsp", WINDOW));
file.push(Entry.construct(".", "icvp", { iconSize: ICON_SIZE, rawAlias }));

await new Promise<void>((res, rej) => {
  file.write(resolve(mount, ".DS_Store"), (err?: Error) => (err ? rej(err) : res()));
}).catch((err: unknown) => {
  die(`could not write .DS_Store: ${err instanceof Error ? err.message : String(err)}`);
});

console.log(`dmg .DS_Store: ${resolve(mount, ".DS_Store")}`);
