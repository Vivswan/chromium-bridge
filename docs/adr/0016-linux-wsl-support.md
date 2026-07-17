# ADR-0016: Linux and WSL dual run modes

- Status: Accepted
- Date: 2026-07-13

## Context

The original Linux implementation reused the macOS install directory and lock
file paths, and the release workflow produced only the macOS Apple Silicon
package. WSL additionally has two deployment topologies at once, Windows
Chrome and WSLg Linux browsers; mixing binaries, manifests, or lock files
between them leaves Native Messaging unable to connect.

## Decision

1. The Linux lock file preferentially lives at
   `$XDG_RUNTIME_DIR/browser-bridge/run.lock`, with the directory at mode
   `0700`; without a runtime dir it falls back, in order, to
   `$XDG_CACHE_HOME`, `~/.cache`, and a UID-isolated temporary directory. The
   lock file itself stays `0600`.
2. Linux installation follows XDG: the binary defaults to
   `${XDG_DATA_HOME:-$HOME/.local/share}/browser-bridge`, and the Native
   Messaging manifests for Google Chrome and Chromium are written into their
   respective XDG config directories.
3. `install.sh` supports `--browser chrome|chromium|both`, defaulting to
   auto-detection; `--skip-extension-build` reuses an already-built
   `extension/dist`.
4. WSL uses two explicit topologies:
   - Windows Chrome: the WSL MCP client launches the Windows-installed `.exe`
     through interop.
   - WSLg Linux Chrome/Chromium: every component installs and runs natively
     inside WSL.
5. The release pipeline adds a prebuilt Linux x64 package; CI verifies with
   isolated XDG directories that the Linux installer writes both the Chrome
   and the Chromium manifest.
6. Cross-platform text files (shell, Python, YAML) are pinned to LF and
   PowerShell scripts to CRLF, so Git working-tree configuration cannot change
   script line endings.

## Outcome

- Linux and WSLg users can install and run browser-bridge natively.
- WSL users can keep driving their everyday Windows Chrome without
  reinstalling a browser inside WSL.
- The three running components must sit within the same operating-system
  boundary; Windows Chrome launching a Linux ELF directly is unsupported, as
  is Linux Chrome reading the Windows Native Messaging registration.
- Prebuilt Linux releases currently cover x64; other Linux architectures still
  build from source.
