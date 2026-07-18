# The desktop app

The Chromium Bridge control panel (`src/apps/desktop`, Tauri v2) is a
complete management surface for the bridge: registration, pairing, trusted
clients, the kill switch, and the audit trail, with no terminal required.
The two capability-granting acts (releasing the kill switch, adding a
client) go through the app's confirm dialog and the user-presence gate
(Touch ID on an enrolled Mac, ADR-0031).
It is co-equal with the CLI; both drive the same engines in
`chromium-bridge-core`, so mixing surfaces cannot fork state. Design record:
[ADR-0029](./adr/0029-desktop-app-management-surface.md); the signing and
entitlement chain it rides on is
[ADR-0026](./adr/0026-tauri-signing-and-entitlement-chain.md).

## Building and running

```sh
just app-dev      # dev loop: builds the host, then Vite dev server + tauri dev
just app-run      # build + sign + verify the real bundle, then launch it
just app-dmg      # build + sign the bundle, then wrap it in a verified .dmg
just app-install  # copy the built app into /Applications
```

`app-run` goes through `just desktop-bundle`, which builds the release host
and the extension, runs `tauri build`, assembles the signed helper bundle for
the host, copies the extension into the app's Resources, stamps the helper
Info.plist with the workspace version, signs inside-out, and re-verifies with
`scripts/check-desktop-signing.ts`. It needs a live provisioning profile
(free-tier profiles expire weekly; see ADR-0026 for the re-mint recipe).

`app-dmg` runs the same pipeline and then packages the verified `.app` into
`target/release/bundle/dmg/chromium-bridge-app-<version>-macos-arm64.dmg`,
with the usual drag-to-/Applications layout. The image is created after the
inside-out re-sign (Tauri's own dmg target would capture the app before the
helper bundle exists), the image itself is codesigned, and the copy inside
the mounted image is re-verified so the checks hold for the artifact that
ships. `app-install` copies an already-built app into /Applications,
replacing any previous install.

Two limits of a free-certificate build, stated plainly: the app runs only on
Macs the embedded provisioning profile lists (this machine, for a profile
Xcode minted here), and it is not notarized, so Gatekeeper warns if the image
is opened on another Mac. The release pipeline can build and publish the same
`.dmg` once its signing secrets are configured; see
[release.md](./release.md).

In the dev loop the app is unsigned, so Secure Enclave operations depend on
the sibling `target/debug/chromium-bridge` and your keychain's mood about
unsigned callers; the signed bundle from `app-run` is the real thing.

Headless checks:

```sh
just desktop-ui-test      # UI unit tests (locale coverage, i18n resolution)
just desktop-check-rust   # UI build, then clippy + tests for the crate
just desktop-check        # re-verify an already-built bundle's signatures
```

`just ci` covers the UI typecheck and unit tests. The Rust crate's clippy and
tests run in the dedicated macOS CI job (`desktop`), since compiling Tauri
needs platform GUI toolchains.

## What to verify by hand (needs a human and a fingerprint)

The GUI itself cannot be clicked headlessly. After `just app-run`:

1. First launch: the Overview page shows a "First launch" banner listing the
   native-messaging manifests it registered for your detected browsers.
   `chromium-bridge doctor --list` from a terminal should agree with the
   Browsers page afterwards.
2. Pairing: on the Pairing page, run Pair (or "Replace key and re-pair" on an
   enrolled machine). Touch ID should prompt; after approval the page shows
   the key fingerprint. Check it against `chromium-bridge enclave-status` and
   against the extension's enrollment screen.
3. Kill switch: engage from the Overview page (one click). `chromium-bridge
   doctor` should report it engaged, and the Audit page should show the
   `kill_engage` record with `surface=core`. Release: the button opens the
   app's confirm dialog first; confirming raises the Touch ID sheet on an
   enrolled Mac, and on success the page names which proof authorized the
   release. Declining the sheet leaves the switch engaged and writes a
   refused `kill_release` record.
4. Audit: the Audit page lists the same records as `chromium-bridge audit`,
   and "Show file" reveals the runtime directory.
5. Clients: the list matches `chromium-bridge list-clients`; revoking is one
   click, removes the entry, and writes a `revoke_client` record. "Add
   client" opens the confirm dialog, then raises Touch ID (enrolled Mac);
   on success the page names the authorizing proof and the entry appears.
6. CLI tool: on the Setup page, Install creates `~/.local/bin/chromium-bridge`
   and `chromium-bridge doctor` works from a terminal (with `~/.local/bin` on
   PATH). Remove deletes exactly that symlink.
7. Extension: the Setup page's "Reveal folder" opens the bundled extension
   directory; loading it via chrome://extensions -> Load unpacked gives a
   working extension.
8. Language: switching the display language on the Setup page swaps every
   view between English, Simplified Chinese, and Traditional Chinese; each
   option in the picker stays in its own language.

Registration, kill, and audit state live in the real user directories (the
same ones the CLI uses); use a throwaway `XDG_RUNTIME_DIR`/`HOME` if you want
an isolated run, and never point browser tests at a daily browser (see
`tests/README.md`).
