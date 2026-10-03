# Quickstart: install and first use

This guide gets chromium-bridge from a download to a working "list my browser tabs" in an MCP client. The way in is the CLI (macOS, Linux, Windows).

Translations: [Simplified Chinese](./quickstart.zh_CN.md), [Traditional Chinese](./quickstart.zh_TW.md).

Before you start, read the security summary in the [README](../README.md#security-first): this tool drives the browser you are logged into, and the confirmations it shows you are the safety model, not friction.

## The CLI (macOS, Linux, Windows)

The CLI needs nothing but the binary, on desktops, headless machines, and CI alike.

1. **Get the binary.** Download and extract the archive for your platform from the [latest release](https://github.com/Vivswan/chromium-bridge/releases/latest). To verify it first, check the published SHA-256 and provenance attestation; commands are in [SECURITY.md](../.github/SECURITY.md#release-artifact-integrity). Or build from source with `cargo build --release`.
2. **Put it somewhere stable.** Registrations point at the binary in place, so a path that will not disappear matters. On Linux, `~/.local/lib/chromium-bridge/` works well; anywhere under your home is fine on macOS. (An AppImage mount or a temp directory is not stable, and `doctor --fix` warns if you try.)
3. **Register it with your browsers:**

   ```sh
   ./chromium-bridge doctor --fix                       # every detected browser
   ./chromium-bridge doctor --fix --browser chrome,brave
   ./chromium-bridge doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                        # variant (macOS/Linux)
   ```

   The repair is idempotent re-registration: on a fresh machine it is the install, after moving the binary it is the fix, and running it twice is harmless. `chromium-bridge doctor --list` shows the state read-only, and `chromium-bridge uninstall` reverses exactly what was written.

4. **Load the extension.** The release archive contains `extension/dist/`; load it via `chrome://extensions`, Developer mode, "Load unpacked" (in a source checkout, build it first and load `build/extension/chrome-mv3`). Restart the browser.

5. **On macOS, pair.** Run `chromium-bridge pair` (Touch ID prompts and the key's fingerprint is printed), then approve that fingerprint on the extension's options page. On macOS the extension requires this enrollment unconditionally (ADR-0032 phase 5 retired the old `requireEnrollment` opt-out) and refuses to act until the pin is in place. Linux and Windows have no Secure Enclave and skip this step.

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

Both are described in [cli.md](./cli.md) and the [threat model](./security/threat-model.md).

## Uninstalling

- `chromium-bridge uninstall` removes the manifests and wrapper scripts this project wrote, and only those. Then delete the binary and remove the extension from the browser.

Enrollment state is separate: `chromium-bridge revoke` deletes the Secure Enclave key, and the extension's options page clears its pin.
