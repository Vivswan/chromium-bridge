# Quickstart: install and first use

This guide gets chromium-bridge from a download to a working "list my browser tabs" in an MCP client. The way in is the CLI (macOS, Linux, Windows).

Before you start, read the security summary in the [README](../README.md#security-first): this tool drives the browser you are logged into, and the confirmations it shows you are the safety model, not friction.

The extension needs Chrome 134 or later; an older browser refuses to load it.

## The CLI (macOS, Linux, Windows)

The CLI needs nothing but the binary, on desktops, headless machines, and CI alike. The one exception today is pairing on macOS (step 5), which needs a build codesigned with an application identifier.

1. **Install it.** Pick one from the [latest release](https://github.com/Vivswan/chromium-bridge/releases/latest); to verify a download first, the commands are in [SECURITY.md](../.github/SECURITY.md#release-artifact-integrity).

   | Channel | Command or click | What it does |
   | --- | --- | --- |
   | macOS `.pkg` | right-click, Open (unsigned for now) | installs `/usr/local/bin/chromium-bridge` and runs step 3 for you |
   | Windows `.msi` | double-click (unsigned for now; SmartScreen warns) | installs under `%LOCALAPPDATA%\Programs\chromium-bridge` for your account, adds it to your PATH, and runs step 3 for you |
   | Linux `.deb` | `sudo dpkg -i chromium-bridge-<tag>-linux-x64.deb` | installs `/usr/bin/chromium-bridge` and runs step 3 for you, machine-wide |
   | Homebrew | `brew install vivswan/tap/chromium-bridge`, once the tap exists ([release.md](./release.md#homebrew-tap)) | installs the binary and runs step 3 for you |
   | archive | extract `chromium-bridge-<tag>-<platform>-<arch>.tar.gz` (`.zip` on Windows) | the binary and `extension/dist`; steps 2 and 3 are yours |

   Or build from source with `cargo build --release`. Windows registration has not yet been tried on a user's machine ([cli.md's Windows note](./cli.md#doctor---fix--uninstall-native-messaging-registration)).
2. **Archive only: put it somewhere stable.** Registrations point at the binary in place, so pick a path that will not disappear: `~/.local/lib/chromium-bridge/` on Linux, anywhere under your home on macOS. An AppImage mount or a temp directory is not stable, and `doctor --fix` warns if you try.
3. **Register it with your browsers.** The .pkg, the .msi and Homebrew did this already, and the .deb did for the browsers installed at the time; the archive needs it (run the binary from its extracted directory with a `./` prefix):

   ```sh
   chromium-bridge doctor --fix                       # every detected browser
   chromium-bridge doctor --fix --browser chrome,brave
   chromium-bridge doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                      # variant (macOS/Linux)
   ```

   Running it twice is harmless, `chromium-bridge doctor --list` shows the state read-only, and `chromium-bridge uninstall` reverses exactly what was written; [cli.md](./cli.md#doctor---fix--uninstall-native-messaging-registration) owns the details.

4. **Load the extension.** The extension's Web Store listing is not published yet ([release.md's Web Store section](./release.md#publishing-to-the-chrome-web-store)): load `extension/dist` from the release archive via `chrome://extensions`, Developer mode, "Load unpacked" (in a source checkout, build it first and load `build/extension/chrome-mv3`). Restart the browser.

   Once the listing exists, [cli.md's pointer table](./cli.md#doctor---fix--uninstall-native-messaging-registration) says which browsers then offer the extension from the pointer step 3 left, and where none is written.

5. **On macOS, pair.** Run `chromium-bridge pair` (Touch ID prompts and the key's fingerprint is printed), then approve that fingerprint on the extension's options page. On macOS the extension requires this enrollment unconditionally (the old `requireEnrollment` opt-out was retired) and refuses to act until the pin is in place.

   Pairing today needs a build codesigned with an application identifier: the plain release binary cannot mint the Enclave key. A later change moves presence to WebAuthn and removes that requirement; it is not implemented yet. Linux and Windows have no Secure Enclave and skip this step.

6. **Connect your MCP client** to the binary's absolute path. For Claude Code:

   ```sh
   claude mcp add chromium-bridge -- /absolute/path/to/chromium-bridge
   ```

   For Claude Desktop and other JSON-configured clients, add an `mcpServers` entry pointing at the same absolute path with no arguments.

The full command reference (pairing, trusted clients, revocation, the kill switch, the audit trail) is in [cli.md](./cli.md).

## What you should see

- `chromium-bridge doctor` reports your browser's registration as `ok` and, once your MCP client has a session open, the server as reachable.
- The extension's toolbar icon shows the connection state.
- The first tool call against a new site raises an approval prompt in the browser; high-risk actions raise a confirmation window; on an enrolled Mac, `page_eval` and `page_upload` raise Touch ID.

## Recommended hardening

Pairing (step 5) is required on macOS and is what upgrades the highest-risk confirmations to hardware Touch ID. One more optional ceremony binds the MCP-client side:

- `chromium-bridge pair-client` creates the trusted-client allowlist. Once it exists, only MCP clients whose attested code identity you approved are served, and any surface can revoke one at any time.

Both are described in [cli.md](./cli.md) and the [security page](./security.md).

## Uninstalling

`chromium-bridge uninstall` removes exactly what `--fix` wrote ([cli.md](./cli.md#doctor---fix--uninstall-native-messaging-registration) says what, and what it refuses). Then remove the binary the way it came:

| Channel | Remove the binary |
| --- | --- |
| macOS `.pkg` | `sudo rm /usr/local/bin/chromium-bridge && sudo pkgutil --forget io.github.vivswan.chromium-bridge` |
| Windows `.msi` | Settings, Apps, Chromium Bridge, Uninstall (it runs `chromium-bridge uninstall` for you) |
| Linux `.deb` | `sudo dpkg -r chromium-bridge` |
| Homebrew | `brew uninstall chromium-bridge` |
| archive | delete the extracted directory |

Enrollment state is separate: `chromium-bridge revoke` deletes the Secure Enclave key, and the extension's options page clears its pin.
