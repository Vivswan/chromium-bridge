# ADR-0015: Windows local run and install support

- Status: Accepted
- Date: 2026-07-13

## Context

The original implementation relied on Unix file permissions, `/dev/urandom`,
POSIX signals, and the macOS Native Messaging manifest directory, so it could
not compile or install on Windows.

## Decision

1. The Windows lock file lives at `%LOCALAPPDATA%\browser-bridge\run.lock`, and
   the random token is generated with `BCryptGenRandom`.
2. Use the Win32 process API to detect and terminate an old MCP Server,
   keeping the new-session takeover semantics.
3. The Chrome Native Messaging manifest points directly at
   `browser-bridge.exe`. On Windows, Chrome appends the caller's
   `chrome-extension://` origin to the command line, and the program uses that
   to enter native-host mode; the explicit `--native-host` flag is kept for
   tests and the Unix wrapper.
4. `install.ps1` places the manifest in `%LOCALAPPDATA%\browser-bridge` and
   registers the absolute path under the current user's
   `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.browser_bridge.host`.
   Installation needs no administrator rights.
5. Windows `rename` does not overwrite an existing file, so a stale target is
   deleted before the new lock file is written. The temporary file is fully
   written and flushed first; if the Native Host happens to read between the
   delete and the rename, the extension recovers through the existing
   two-second reconnect mechanism.

## Outcome

- The Rust backend compiles and runs natively on Windows.
- Windows users can install locally from source with `install.ps1`.
- A prebuilt Windows release package is not yet in the release workflow; the
  current release still ships only the macOS Apple Silicon package.
- Edge is out of scope.
