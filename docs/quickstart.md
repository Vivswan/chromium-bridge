# Quickstart: install and first use

This guide gets chromium-bridge from a download to a working "list my browser
tabs" in an MCP client. There are two equal ways in: the desktop app (macOS,
no terminal) and the CLI (macOS, Linux, Windows). Both drive the same engine
and write the same registrations, so you can start with one and repair or
remove with the other.

Translations: [Simplified Chinese](./quickstart.zh_CN.md),
[Traditional Chinese](./quickstart.zh_TW.md).

Before you start, read the security summary in the
[README](../README.md#security-first): this tool drives the browser you are
logged into, and the confirmations it shows you are the safety model, not
friction.

## Path A: the desktop app (macOS)

> App downloads are not published yet (releases currently carry the CLI
> archive only). Until they are, build and launch the app from a source
> checkout with `moon run run-app`, or use path B.

1. **Install the app.** Get `Chromium Bridge.app` (see the note above) and
   open it. On first launch it registers its bundled native-messaging
   host with every Chromium browser it detects and lists exactly what it
   wrote. Nothing else on your system is touched.
2. **Load the extension.** On the app's Setup page, click "Reveal folder".
   In your browser, open `chrome://extensions`, turn on Developer mode, click
   "Load unpacked", and pick the revealed folder. Then restart the browser so
   it re-reads its native-messaging registrations.
3. **Pair with Touch ID.** On the app's Pairing page, click Pair; Touch ID
   prompts, and the page shows the new key's fingerprint. Approve that same
   fingerprint on the extension's options page. On macOS the extension
   requires this enrollment by default (`requireEnrollment`) and refuses to
   act until the pin is in place
   ([ADR-0021](./adr/0021-enrollment-ceremony.md)).
4. **Give your MCP client the command.** On the Setup page, click Install to
   place the `chromium-bridge` command at `~/.local/bin/chromium-bridge`,
   then register it with your client. For Claude Code this is the one command
   in this whole path:

   ```sh
   claude mcp add chromium-bridge -- "$HOME/.local/bin/chromium-bridge"
   ```

   For Claude Desktop and other JSON-configured clients, add an `mcpServers`
   entry pointing at the same absolute path with no arguments.

5. **Try it.** Ask the client to "list my browser tabs". The first time you
   target a new site, click the Chromium Bridge toolbar icon and approve the
   origin.

The app stays useful after setup: it is the control panel for browser
registrations, Touch ID enrollment, trusted MCP clients, the kill switch,
and the audit trail. See [desktop-app.md](./desktop-app.md).

## Path B: the CLI (macOS, Linux, Windows)

The CLI needs nothing but the binary. It is the natural path on Linux and
Windows, on headless machines, and in CI.

1. **Get the binary.** Download and extract the archive for your platform
   from the
   [latest release](https://github.com/Vivswan/chromium-bridge/releases/latest).
   To verify it first, check the published SHA-256 and provenance
   attestation; commands are in
   [SECURITY.md](../SECURITY.md#release-artifact-integrity). Or build from
   source with `cargo build --release`.
2. **Put it somewhere stable.** Registrations point at the binary in place,
   so a path that will not disappear matters. On Linux,
   `~/.local/lib/chromium-bridge/` works well; anywhere under your home is
   fine on macOS. (An AppImage mount or a temp directory is not stable, and
   `doctor --fix` warns if you try.)
3. **Register it with your browsers:**

   ```sh
   ./chromium-bridge doctor --fix                       # every detected browser
   ./chromium-bridge doctor --fix --browser chrome,brave
   ./chromium-bridge doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                        # variant (macOS/Linux)
   ```

   The repair is idempotent re-registration: on a fresh machine it is the
   install, after moving the binary it is the fix, and running it twice is
   harmless. `chromium-bridge doctor --list` shows the state read-only, and
   `chromium-bridge uninstall` reverses exactly what was written.

4. **Load the extension.** The release archive contains `extension/dist/`;
   load it via `chrome://extensions`, Developer mode, "Load unpacked" (in a
   source checkout, build it first and load
   `build/extension/chrome-mv3`). Restart the browser.

5. **On macOS, pair.** Run `chromium-bridge pair` (Touch ID prompts and the
   key's fingerprint is printed), then approve that fingerprint on the
   extension's options page. The extension requires enrollment on macOS by
   default and refuses to act until the pin is in place. Linux and Windows
   have no Secure Enclave and skip this step.

6. **Connect your MCP client** to the binary's absolute path, as in path A.

The full command reference (pairing, trusted clients, revocation, the kill
switch, the audit trail) is in [cli.md](./cli.md).

## After either path: what you should see

- `chromium-bridge doctor` reports your browser's registration as `ok` and,
  once your MCP client has a session open, the server as reachable.
- The extension's toolbar icon shows the connection state.
- The first tool call against a new site raises an approval prompt in the
  browser; high-risk actions raise a confirmation window; on an enrolled Mac,
  `page_eval` and `page_upload` raise Touch ID.

## Recommended hardening

Pairing (path A step 3 / path B step 5) is required on macOS and is what
upgrades the highest-risk confirmations to hardware Touch ID. One more
optional ceremony binds the MCP-client side:

- `chromium-bridge pair-client` (or the app's Clients page) creates the
  trusted-client allowlist. Once it exists, only MCP clients whose attested
  code identity you approved are served, and any surface can revoke one at
  any time.

Both are described in [cli.md](./cli.md) and the
[threat model](./security/threat-model.md).

## Uninstalling

- App path: quit the app, remove `Chromium Bridge.app`, and remove the
  extension from `chrome://extensions`. Registrations point into the app
  bundle; run `chromium-bridge uninstall` (from the Setup page's CLI install
  or any copy of the binary) to clear them.
- CLI path: `chromium-bridge uninstall` removes the manifests and wrapper
  scripts this project wrote, and only those. Then delete the binary and
  remove the extension from the browser.

Enrollment state is separate: `chromium-bridge revoke` deletes the Secure
Enclave key, and the extension's options page clears its pin.
