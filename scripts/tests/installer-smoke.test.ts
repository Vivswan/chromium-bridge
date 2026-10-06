import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { NATIVE_HOST_ID, PINNED_EXTENSION_ID } from "../../src/packages/shared/src/identity.gen.ts";
import { type Host, smoke } from "../installer-smoke.ts";
import type { Finished } from "../lib.ts";
import { pkgIdentifier } from "../release-package.ts";

// What would drift silently: the smoke is the only thing between an installer that lays nothing down and
// a green job, and it runs on runners nobody watches. Each platform's command sequence is pinned whole
// against a conforming fake runner, and each check kind is shown failing on the one wrong answer it
// exists to catch (a binary from another build, a registration the uninstall left behind, a surviving
// file, a key the uninstall left behind or that reg could not read).

interface Fake extends Host {
  calls: string[][];
  made: string[];
}

const ok = (stdout = ""): Finished => ({ exitCode: 0, stdout, stderr: "" });
const notFound: Finished = {
  exitCode: 1,
  stdout: "",
  stderr: "ERROR: The system was unable to find the specified registry key or value.\r\n",
};
// `doctor --list` prints a user and a system row per browser; the fake registers both (the pkg and msi the
// user one, the deb the system one, which Linux lists without a pointer).
const registered =
  "  chrome    detected      user    manifest ok         pointer ok         C:\\x\n" +
  "  chrome    detected      system  manifest ok         pointer n/a        /etc/x\n";
const unregistered =
  "  chrome    detected      user    manifest missing    pointer missing    C:\\x\n" +
  "  chrome    detected      system  manifest missing    pointer n/a        /etc/x\n";

/**
 * A runner on which every install, version, list, and uninstall answers as the real one should: the list
 * rows read registered until `uninstall` (or the deb's removal, whose prerm runs it) ran, then unregistered.
 */
function conforming(overrides: Partial<Fake> = {}): Fake {
  let uninstalled = false;
  const fake: Fake = {
    calls: [],
    made: [],
    run(argv) {
      fake.calls.push(argv);
      if (argv.includes("uninstall") || argv.includes("-r")) uninstalled = true;
      if (argv.includes("--version")) return ok("chromium-bridge 1.2.3\n");
      if (argv.includes("--list")) return ok(uninstalled ? unregistered : registered);
      if (argv[0] === "reg") return notFound;
      return ok();
    },
    presence: () => "absent",
    mkdir: (path) => {
      fake.made.push(path);
    },
    readLog: () => "",
    log: () => {},
    ...overrides,
  };
  return fake;
}

const local = "C:\\Users\\example-user\\AppData\\Local";
const exe = join(local, "Programs", "chromium-bridge", "chromium-bridge.exe");
const home = "/home/user";
const wrapper = join(home, ".chromium-bridge", "run-host-chrome.sh");
const macBin = "/usr/local/bin/chromium-bridge";
const roots = { home, localAppData: local };

describe("the command sequence per platform, against a conforming runner", () => {
  test.each<[string, string, string[][], string[]]>([
    [
      "macos",
      "cb.pkg",
      [
        ["sudo", "installer", "-pkg", "cb.pkg", "-target", "/"],
        ["stat", "-f", "%Su", "/dev/console"],
        ["sudo", "grep", "-F", "chromium-bridge", "/var/log/install.log"],
        [macBin, "--version"],
        ["pkgutil", "--pkg-info", pkgIdentifier],
        [macBin, "doctor", "--list"],
        [macBin, "uninstall"],
        [macBin, "doctor", "--list"],
        ["sudo", "pkgutil", "--forget", pkgIdentifier],
        ["sudo", "rm", macBin],
      ],
      [],
    ],
    [
      "linux",
      "cb.deb",
      [
        ["sudo", "dpkg", "-i", "cb.deb"],
        ["/usr/bin/chromium-bridge", "--version"],
        ["dpkg", "-s", "chromium-bridge"],
        ["/usr/bin/chromium-bridge", "doctor", "--list"],
        ["sudo", "dpkg", "-r", "chromium-bridge"],
      ],
      [],
    ],
    [
      "windows",
      "cb.msi",
      [
        ["msiexec", "/i", "cb.msi", "/qn", "/norestart", "/l*v", "install.log"],
        [exe, "--version"],
        [exe, "doctor", "--list"],
        ["msiexec", "/x", "cb.msi", "/qn", "/norestart", "/l*v", "uninstall.log"],
        ["reg", "query", `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${NATIVE_HOST_ID}`],
        ["reg", "query", `HKCU\\Software\\Google\\Chrome\\Extensions\\${PINNED_EXTENSION_ID}`],
      ],
      [join(local, "Google", "Chrome", "User Data")],
    ],
  ])("%s", (platform, installer, calls, made) => {
    const fake = conforming();
    smoke(platform, installer, "1.2.3", fake, roots);
    expect({ calls: fake.calls, made: fake.made }).toEqual({ calls, made });
  });
});

/** A runner that answers like the conforming one except where `answer` overrides a command; every call is recorded. */
function answering(answer: (argv: string[]) => Finished | undefined): Partial<Fake> {
  const base = conforming();
  return {
    calls: base.calls,
    run: (argv) => {
      const answered = answer(argv);
      if (answered === undefined) return base.run(argv);
      base.calls.push(argv);
      return answered;
    },
  };
}

test("a failed pkg install still logs the console owner and the package's install.log lines before failing", () => {
  const fake = conforming(
    answering((argv) =>
      argv[1] === "installer"
        ? { exitCode: 1, stdout: "", stderr: "installer: failed\n" }
        : undefined,
    ),
  );
  expect(() => smoke("macos", "cb.pkg", "1.2.3", fake, roots)).toThrow(
    /^sudo installer -pkg cb\.pkg -target \/ exited 1, expected 0:\ninstaller: failed/,
  );
  expect(fake.calls).toEqual([
    ["sudo", "installer", "-pkg", "cb.pkg", "-target", "/"],
    ["stat", "-f", "%Su", "/dev/console"],
    ["sudo", "grep", "-F", "chromium-bridge", "/var/log/install.log"],
  ]);
});

describe("each check fails on the one wrong answer it exists to catch", () => {
  test.each<[string, string, Partial<Fake>, RegExp]>([
    [
      "a binary from another build",
      "windows",
      answering((argv) => (argv.includes("--version") ? ok("chromium-bridge 1.2.2\n") : undefined)),
      /--version printed "chromium-bridge 1\.2\.2\\n", expected 1\.2\.3/,
    ],
    [
      "a binary whose version merely starts with the expected one",
      "windows",
      answering((argv) =>
        argv.includes("--version") ? ok("chromium-bridge 1.2.30\n") : undefined,
      ),
      /--version printed "chromium-bridge 1\.2\.30\\n", expected 1\.2\.3/,
    ],
    [
      "a list row without the pointer",
      "windows",
      answering((argv) =>
        argv.includes("--list")
          ? ok("  chrome    detected      user    manifest ok         pointer missing    C:\\x\n")
          : undefined,
      ),
      /doctor --list printed nothing matching/,
    ],
    [
      "a registration the macOS uninstall left behind",
      "macos",
      answering((argv) => (argv.includes("--list") ? ok(registered) : undefined)),
      /doctor --list printed nothing matching \/chrome\\s\+detected\\s\+user\\s\+manifest missing/,
    ],
    [
      "a wrapper the macOS uninstall left behind, outside doctor's view",
      "macos",
      { presence: (path) => (path === wrapper ? "present" : "absent") },
      /^expected \/home\/user\/\.chromium-bridge\/run-host-chrome\.sh to be gone$/,
    ],
    [
      "an install that fails, with the log's tail quoted",
      "windows",
      {
        ...answering((argv) =>
          argv[0] === "msiexec" ? { exitCode: 1603, stdout: "", stderr: "" } : undefined,
        ),
        readLog: () =>
          "MSI (s) (A0:B4) Note: 1: 1708\nMSI (s) (A0:B4) Product: Chromium Bridge -- Installation failed.\n",
      },
      /msiexec \/i cb\.msi .* exited 1603, expected 0; log tail:\nMSI \(s\) \(A0:B4\) Note: 1: 1708\nMSI .*Installation failed\.$/,
    ],
    [
      "a binary the uninstall left behind",
      "windows",
      { presence: (path) => (path === exe ? "present" : "absent") },
      new RegExp(`^expected ${exe.replaceAll("\\", "\\\\")} to be gone$`),
    ],
    [
      "a registry key the uninstall left behind",
      "windows",
      answering((argv) =>
        argv[0] === "reg"
          ? ok("HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts\\x\n")
          : undefined,
      ),
      /^reg query HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\\S+ exited 0, expected the key to be absent:\nHKEY_CURRENT_USER/,
    ],
    [
      "a registry key reg was not allowed to read is not an absent key",
      "windows",
      answering((argv) =>
        argv[0] === "reg"
          ? { exitCode: 1, stdout: "", stderr: "ERROR: Access is denied.\r\n" }
          : undefined,
      ),
      /^reg query \S+ exited 1, expected the key to be absent:\nERROR: Access is denied\./,
    ],
  ])("%s", (_name, platform, overrides, failure) => {
    const installer = platform === "macos" ? "cb.pkg" : "cb.msi";
    expect(() => smoke(platform, installer, "1.2.3", conforming(overrides), roots)).toThrow(
      failure,
    );
  });
});
