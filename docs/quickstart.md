# Quickstart: install and first use

This guide gets genkan from a download to a working "list my browser tabs" in an MCP client. The way in is the CLI (macOS, Linux, Windows).

Before you start, read the security summary in the [README](../README.md#security-first): this tool drives the browser you are logged into, and the confirmations it shows you are the safety model, not friction.

The extension needs Chrome 134 or later; an older browser refuses to load it.

## The CLI (macOS, Linux, Windows)

The CLI needs nothing but the binary, on desktops, headless machines, and CI alike.

1. **Install it.** Pick one from the [latest release](https://github.com/Vivswan/genkan/releases/latest); to verify a download first, the commands are in [SECURITY.md](../.github/SECURITY.md#release-artifact-integrity).

   | Channel | Command or click | What it does |
   | --- | --- | --- |
   | macOS `.pkg` | right-click, Open (unsigned for now) | installs `/usr/local/bin/genkan` and runs step 3 for you |
   | Windows `.msi` | double-click (unsigned for now; SmartScreen warns) | installs under `%LOCALAPPDATA%\Programs\genkan` for your account, adds it to your PATH, and runs step 3 for you |
   | Linux `.deb` | `sudo dpkg -i genkan-<tag>-linux-x64.deb` | installs `/usr/bin/genkan` and runs step 3 for you, machine-wide |
   | Homebrew | `brew install vivswan/tap/genkan`, once the tap exists ([release.md](./release.md#homebrew-tap)) | installs the binary and runs step 3 for you |
   | archive | extract `genkan-<tag>-<platform>-<arch>.tar.gz` (`.zip` on Windows) | the binary and `extension/dist`; steps 2 and 3 are yours |

   Or build from source with `cargo build --release`. Windows registration has not yet been tried on a user's machine ([cli.md's Windows note](./cli.md#doctor---fix--uninstall-native-messaging-registration)).
2. **Archive only: put it somewhere stable.** Registrations point at the binary in place, so pick a path that will not disappear: `~/.local/lib/genkan/` on Linux, anywhere under your home on macOS. An AppImage mount or a temp directory is not stable, and `doctor --fix` warns if you try.
3. **Register it with your browsers.** The .pkg, the .msi and Homebrew did this already, and the .deb did for the browsers installed at the time; the archive needs it (run the binary from its extracted directory with a `./` prefix):

   ```sh
   genkan doctor --fix                       # every detected browser
   genkan doctor --fix --browser chrome,brave
   genkan doctor --fix --manifest-dir DIR    # an unlisted Chromium
                                                      # variant (macOS/Linux)
   ```

   Running it twice is harmless, `genkan doctor --list` shows the state read-only, and `genkan uninstall` reverses exactly what was written; [cli.md](./cli.md#doctor---fix--uninstall-native-messaging-registration) owns the details.

4. **Load the extension.** The extension's Web Store listing is not published yet ([release.md's Web Store section](./release.md#publishing-to-the-chrome-web-store)): load `extension/dist` from the release archive via `chrome://extensions`, Developer mode, "Load unpacked" (in a source checkout, build it first and load `build/extension/chrome-mv3`). Restart the browser.

   Once the listing exists, [cli.md's pointer table](./cli.md#doctor---fix--uninstall-native-messaging-registration) says which browsers then offer the extension from the pointer step 3 left, and where none is written.

5. **Pair.** Run `genkan pair`: it asks for a confirmation typed on the terminal, mints the host key, and prints the key's fingerprint. Approve that fingerprint on the extension's options page; the extension refuses to act until the pin is in place, on every platform ([cli.md](./cli.md#enrollment-pair--revoke--enclave-status) owns the ceremony and its flags).

6. **Enroll (recommended).** From the options page's identity section, enroll your browser's authenticator. The first enrollment on the machine is trust on first use; every later one needs a tap from an authenticator already enrolled.

7. **Connect your MCP client** to the binary's absolute path. For Claude Code:

   ```sh
   claude mcp add genkan -- /absolute/path/to/genkan
   ```

   For Claude Desktop and other JSON-configured clients, add an `mcpServers` entry pointing at the same absolute path with no arguments.

The full command reference (pairing, trusted clients, revocation, the kill switch, the audit trail) is in [cli.md](./cli.md).

## What you should see

`genkan doctor` with Chrome registered and the MCP server running (your MCP client starts it), captured on a fresh macOS home:

```text
$ genkan doctor
genkan doctor - v0.1.0
platform:        macos/aarch64
lock file:       /tmp/quickstart-home/Library/Application Support/genkan/run.lock
  present: yes
  endpoint: /tmp/quickstart-home/Library/Application Support/genkan/run.sock
  pid:     77652
  secret:  <redacted, 32 chars>
mcp server:      reachable (socket connect OK)
kill switch:     off (bridge activity permitted)
policy baseline: none yet (pre-cutover; the extension keeps enforcing its deny baseline until `genkan policy set` or the options page's Security policy section signs a baseline)
native manifests: (host id com.vivswan.genkan.host)
  chrome    detected      user    manifest ok         /tmp/quickstart-home/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  ok         /tmp/quickstart-home/Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  chromium  not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/Chromium/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Application Support/Chromium/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/Chromium/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  brave     not detected  user    manifest ok         /tmp/quickstart-home/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json (reads chrome's)
                          system  manifest missing    /Library/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json (reads chrome's)
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  edge      not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/Microsoft Edge/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Microsoft/Edge/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/Microsoft Edge/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  vivaldi   not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/Vivaldi/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Application Support/Vivaldi/NativeMessagingHosts/com.vivswan.genkan.host.json
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/Vivaldi/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
  opera     not detected  user    manifest missing    /tmp/quickstart-home/Library/Application Support/com.operasoftware.Opera/NativeMessagingHosts/com.vivswan.genkan.host.json
                          system  manifest missing    /Library/Google/Chrome/NativeMessagingHosts/com.vivswan.genkan.host.json (reads chrome's)
                          user    pointer  missing    /tmp/quickstart-home/Library/Application Support/com.operasoftware.Opera/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json
                          system  pointer  missing    /Library/Application Support/Google/Chrome/External Extensions/mkjjlmjbcljpcfkfadfmhblmmddkdihf.json

note: the checks above cover the MCP server + native-host bridge only.
They do NOT confirm the Chrome extension is loaded and connected. Verify
that via the Genkan toolbar icon (approve the target site) and
the extension's Service Worker console at chrome://extensions.

OK
```

- The capture ran in a scratch home at `/tmp/quickstart-home`. On your machine the paths that start with it sit under your own home directory by default, and Linux and Windows print their own locations.
- The extension's toolbar icon shows the connection state.
- The first tool call against a new site raises an approval prompt in the browser; high-risk actions raise a confirmation window.

## Recommended hardening

Pairing (step 5) is required on every platform. Enrolling (step 6) is recommended: a browser with no enrolled authenticator answers a presence request, such as a kill-switch release, in the confirmation window instead of with a tap. One more optional ceremony binds the MCP-client side:

- `genkan pair-client` creates the trusted-client allowlist. Once it exists, only MCP clients whose attested code identity you approved are served, and any surface can revoke one at any time.

All three are described in [cli.md](./cli.md) and the [security page](./security.md).

## Uninstalling

`genkan uninstall` removes exactly what `--fix` wrote ([cli.md](./cli.md#doctor---fix--uninstall-native-messaging-registration) says what, and what it refuses). Then remove the binary the way it came:

| Channel | Remove the binary |
| --- | --- |
| macOS `.pkg` | `sudo rm /usr/local/bin/genkan && sudo pkgutil --forget io.github.vivswan.genkan` |
| Windows `.msi` | Settings, Apps, Genkan, Uninstall (it runs `genkan uninstall` for you) |
| Linux `.deb` | `sudo dpkg -r genkan` |
| Homebrew | `brew uninstall genkan` |
| archive | delete the extracted directory |

Pairing state is separate: `genkan revoke --all` deletes the host key and forgets every browser and trusted client, and the extension's options page clears its pin.

The authenticators enrolled in step 6 live in `trust.json`. `revoke <browser>` forgets the ones enrolled under that browser's label, which is `default` for every browser on a shared unlabelled manifest, as [cli.md](./cli.md#enrollment-pair--revoke--enclave-status) explains. `revoke --all` starts over, and a `trust.json` that `doctor` cannot read is the [troubleshooting page's](./troubleshooting.md#doctor-says-the-kill-state-or-the-trust-record-is-unreadable) case.
