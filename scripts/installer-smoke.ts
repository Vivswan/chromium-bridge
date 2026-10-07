#!/usr/bin/env bun

// Platform facts installers.yml's smoke rests on: msiexec reports its reason only in a UTF-16LE log, and the pkg
// postinstall's output lands in /var/log/install.log.

import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { NATIVE_HOST_ID, PINNED_EXTENSION_ID } from "../src/packages/shared/generated/identity.ts";
import {
  CommandChecks,
  cargoVersion,
  die,
  type Finished,
  type Presence,
  presenceOf,
  requiredEnv,
} from "./lib.ts";
import { pkgIdentifier } from "./release-package.ts";

export interface Host {
  run: (argv: string[]) => Finished;
  presence: (path: string) => Presence;
  mkdir: (path: string) => void;
  readLog: (path: string) => string;
  log: (line: string) => void;
}

// The `doctor --list` rows the smoke matches; Linux writes no pointer, so its row reads n/a.
export const chromeRegistered = /chrome\s+detected\s+user\s+manifest ok\s+pointer ok/;
export const chromeUnregistered = /chrome\s+detected\s+user\s+manifest missing\s+pointer missing/;
export const chromeSystemRegistered = /chrome\s+detected\s+system\s+manifest ok\s+pointer n\/a/;

const keyNotFound = /unable to find the specified registry key/;

class Steps extends CommandChecks {
  constructor(
    private readonly host: Host,
    private readonly expected: string,
  ) {
    super(host.run, host.log, undefined, host.presence);
  }

  /** `--version` prints exactly Cargo's version: the installed binary is the one this checkout built. */
  version(binary: string): void {
    const stdout = this.ok(binary, "--version");
    if (stdout.trim() !== `chromium-bridge ${this.expected}`) {
      throw new Error(
        `${binary} --version printed ${JSON.stringify(stdout)}, expected ${this.expected}`,
      );
    }
  }

  msiexec(verb: string, installer: string, log: string): void {
    const argv = ["msiexec", verb, installer, "/qn", "/norestart", "/l*v", log];
    const finished = this.run(...argv);
    if (finished.exitCode !== 0) {
      const tail = this.host.readLog(log).trimEnd().split(/\r?\n/).slice(-40).join("\n");
      throw new Error(
        `${argv.join(" ")} exited ${finished.exitCode}, expected 0; log tail:\n${tail}`,
      );
    }
  }

  /** `reg query` exits 1 both for a missing key and for one it was not allowed to read, so only its not-found text
   * counts as absent; a key it could not read is a failed check, not a clean uninstall. */
  absentKey(key: string): void {
    const argv = ["reg", "query", key];
    const finished = this.run(...argv);
    if (finished.exitCode === 0 || !keyNotFound.test(finished.stderr)) {
      throw new Error(
        `${argv.join(" ")} exited ${finished.exitCode}, expected the key to be absent:\n${finished.stdout}${finished.stderr}`,
      );
    }
  }
}

function macos(installer: string, steps: Steps, home: string): void {
  const binary = "/usr/local/bin/chromium-bridge";
  const install = ["sudo", "installer", "-pkg", installer, "-target", "/"];
  const installed = steps.run(...install);
  steps.run("stat", "-f", "%Su", "/dev/console");
  steps.run("sudo", "grep", "-F", "chromium-bridge", "/var/log/install.log");
  steps.exited0(install, installed);
  steps.version(binary);
  steps.ok("pkgutil", "--pkg-info", pkgIdentifier);
  // The wrapper is outside doctor's view once the manifest is gone, so it is checked by path.
  steps.outputMatches(chromeRegistered, binary, "doctor", "--list");
  steps.ok(binary, "uninstall");
  steps.outputMatches(chromeUnregistered, binary, "doctor", "--list");
  // Brave reads Chrome's per-user directory on macOS, so Chrome's wrapper is the unlabeled one.
  steps.absent(join(home, ".chromium-bridge", "run-host.sh"));
  steps.ok("sudo", "pkgutil", "--forget", pkgIdentifier);
  steps.ok("sudo", "rm", binary);
  steps.absent(binary);
}

function linux(installer: string, steps: Steps): void {
  const binary = "/usr/bin/chromium-bridge";
  steps.ok("sudo", "dpkg", "-i", installer);
  steps.version(binary);
  steps.ok("dpkg", "-s", "chromium-bridge");
  // The postinst registered machine-wide; the runner's own account reads that row as a user would.
  steps.outputMatches(chromeSystemRegistered, binary, "doctor", "--list");
  steps.ok("sudo", "dpkg", "-r", "chromium-bridge");
  steps.absent(binary);
  // The prerm's `uninstall --system` ran before the binary went; its artifacts are checked by path.
  steps.absent(`/etc/opt/chrome/native-messaging-hosts/${NATIVE_HOST_ID}.json`);
  // Chrome's system directory is shared with Brave, so its wrapper is the unlabeled one.
  steps.absent("/var/lib/chromium-bridge/run-host.sh");
}

function windows(installer: string, steps: Steps, host: Host, localAppData: string): void {
  // Detection on Windows is the profile directory; the runner's Chrome has never been started.
  host.mkdir(join(localAppData, "Google", "Chrome", "User Data"));
  steps.msiexec("/i", installer, "install.log");
  const binary = join(localAppData, "Programs", "chromium-bridge", "chromium-bridge.exe");
  steps.version(binary);
  steps.outputMatches(chromeRegistered, binary, "doctor", "--list");
  steps.msiexec("/x", installer, "uninstall.log");
  steps.absent(binary);
  steps.absent(join(localAppData, "chromium-bridge", `${NATIVE_HOST_ID}.json`));
  steps.absentKey(`HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${NATIVE_HOST_ID}`);
  steps.absentKey(`HKCU\\Software\\Google\\Chrome\\Extensions\\${PINNED_EXTENSION_ID}`);
}

export interface Roots {
  home?: string;
  localAppData?: string;
}

export function smoke(
  platform: string,
  installer: string,
  version: string,
  host: Host,
  roots: Roots,
): void {
  const steps = new Steps(host, version);
  if (platform === "macos") {
    if (roots.home === undefined) throw new Error("HOME is not set");
    macos(installer, steps, roots.home);
  } else if (platform === "linux") {
    linux(installer, steps);
  } else if (platform === "windows") {
    if (roots.localAppData === undefined) throw new Error("LOCALAPPDATA is not set");
    windows(installer, steps, host, roots.localAppData);
  } else {
    throw new Error(`no installer smoke is defined for platform ${platform}`);
  }
}

if (import.meta.main) {
  const host: Host = {
    run(argv) {
      const run = Bun.spawnSync(argv, { stdout: "pipe", stderr: "pipe" });
      return {
        exitCode: run.exitCode,
        stdout: run.stdout.toString(),
        stderr: run.stderr.toString(),
      };
    },
    presence: presenceOf,
    mkdir: (path) => mkdirSync(path, { recursive: true }),
    readLog: (path) => readFileSync(path).toString("utf16le"),
    log: console.log,
  };
  try {
    smoke(requiredEnv("PLATFORM"), requiredEnv("INSTALLER"), cargoVersion(), host, {
      home: process.env.HOME,
      localAppData: process.env.LOCALAPPDATA,
    });
  } catch (error) {
    die((error as Error).message);
  }
  console.log("installer smoke: every check passed");
}
