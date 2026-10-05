// Temp dirs and child processes this process owns. Each dir records the owning pid; on
// SIGTERM/SIGINT/SIGHUP (a `finally` never runs on those) every owned child is stopped and every owned
// dir removed, and a startup sweep clears the dirs a run killed outright left behind. Node builtins
// only, like the driver that imports it.

import type { ChildProcess } from "node:child_process";
import { once } from "node:events";
import { lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";

/** Names the creating process in each dir; the sweep judges staleness by it. */
export const OWNER_FILE = "harness.pid";

const owned = new Set<string>();

/** A fresh dir under the OS temp dir, recorded as this process's. Owned before the record is written, so a failed write still gets removed. */
export function ownedTempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  owned.add(dir);
  writeFileSync(join(dir, OWNER_FILE), `${process.pid}\n`);
  return dir;
}

/** Remove a dir this process created. A failure throws: a dir that survives is reported, never ignored. */
export function removeOwnedDir(dir: string): void {
  rmSync(dir, { recursive: true });
  owned.delete(dir);
}

/** Remove every dir still owned; the ones that survive are reported on stderr and returned. */
export function removeAllOwnedDirs(): string[] {
  const survived: string[] = [];
  for (const dir of [...owned].sort()) {
    try {
      removeOwnedDir(dir);
    } catch (error) {
      survived.push(dir);
      console.error(`[harness-smoke] could not remove ${dir}: ${(error as Error).message}`);
    }
  }
  return survived;
}

/** Whether a process `pid` exists. Only "no such process" reads as dead: another user's process, or any other probe failure, keeps the dir. */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

/** pid_t is a 32-bit int everywhere this driver runs; a larger value names no process. */
const PID_MAX = 2 ** 31 - 1;

/** The pid recorded in `dir`, or undefined when there is no record. A record that cannot be read, or does not spell one positive pid, throws: the sweep must not mistake it for an absent owner. */
function recordedOwner(dir: string): number | undefined {
  const record = join(dir, OWNER_FILE);
  let text: string;
  try {
    text = readFileSync(record, "utf8");
  } catch (error) {
    // A dangling symlink also reads ENOENT; an entry that exists is an unreadable record, not a missing one.
    if (
      (error as NodeJS.ErrnoException).code === "ENOENT" &&
      lstatSync(record, { throwIfNoEntry: false }) === undefined
    ) {
      return undefined;
    }
    throw error;
  }
  const digits = /^[1-9][0-9]*$/.exec(text.trim());
  const pid = digits === null ? Number.NaN : Number(digits[0]);
  if (!(pid <= PID_MAX)) throw new Error(`malformed ${OWNER_FILE}: ${JSON.stringify(text)}`);
  return pid;
}

/**
 * Remove the dirs under `root` with one of `prefixes` whose recorded creating process is gone: the
 * heal for a run killed before its `finally`. A dir with no record, an unreadable one, or a live pid
 * is never touched. Prints and returns what it removed.
 */
export function sweepStaleDirs(prefixes: readonly string[], root: string): string[] {
  const removed: string[] = [];
  const entries = readdirSync(root, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name),
  );
  for (const entry of entries) {
    // isDirectory() is false for a symlink, so a link named like ours is left alone.
    if (!entry.isDirectory() || !prefixes.some((prefix) => entry.name.startsWith(prefix))) continue;
    const dir = join(root, entry.name);
    let owner: number | undefined;
    try {
      owner = recordedOwner(dir);
    } catch (error) {
      console.error(
        `[harness-smoke] kept ${dir}: owner record unreadable (${(error as Error).message})`,
      );
      continue;
    }
    if (owner === undefined || pidAlive(owner)) continue;
    try {
      rmSync(dir, { recursive: true });
    } catch (error) {
      console.error(
        `[harness-smoke] could not remove stale dir ${dir}: ${(error as Error).message}`,
      );
      continue;
    }
    removed.push(dir);
    console.error(`[harness-smoke] removed stale dir ${dir} (owner pid ${owner} is gone)`);
  }
  return removed;
}

/** The in-flight signal teardown, once a terminating signal has arrived. */
let terminating: Promise<void> | undefined;

/** Stop every owned child still running and wait for each to be reaped, then remove every owned dir, when a terminating signal arrives; then exit by that signal so the parent sees it. */
export function teardownOnSignals(): void {
  for (const signal of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    // A once-listener is gone by the time the signal is re-sent, so the default action takes it. A
    // second signal of another kind joins the first teardown instead of starting an empty one.
    process.once(signal, () => {
      terminating ??= killOwnedChildren().then(() => {
        removeAllOwnedDirs();
        process.kill(process.pid, signal);
      });
    });
  }
}

/**
 * Resolves at once unless a signal teardown is in flight, and then never: the re-raised signal ends
 * the process first. Normal completion awaits this before exiting, because the signal that kills a
 * probe's child also completes the probe, and a `process.exit` there would cut the reaping short.
 */
export function joinSignalTeardown(): Promise<void> {
  return terminating ?? Promise.resolve();
}

const children = new Set<ChildProcess>();

/** Register a child this process spawned, so a terminating signal stops it before the dirs it uses go. */
export function ownedChild(child: ChildProcess): ChildProcess {
  children.add(child);
  child.once("exit", () => children.delete(child));
  return child;
}

/** A SIGKILLed child always exits; the bound only keeps a stuck wait from blocking the signal path. */
const CHILD_EXIT_WAIT_MS = 5_000;

/**
 * SIGKILL every registered child that is still running and wait for its exit event, which is the
 * parent reaping it: a child left unreaped at exit becomes an orphan, and under an init that does not
 * reap (a CI container) a zombie that still reads as alive.
 */
async function killOwnedChildren(): Promise<void> {
  const running = [...children].filter(
    (child) => child.pid !== undefined && child.exitCode === null && child.signalCode === null,
  );
  children.clear();
  await Promise.all(
    running.map((child) => {
      const exited = once(child, "exit");
      child.kill("SIGKILL");
      return Promise.race([exited, setTimeout(CHILD_EXIT_WAIT_MS)]);
    }),
  );
}
