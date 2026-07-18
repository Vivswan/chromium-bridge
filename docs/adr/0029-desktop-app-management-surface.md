# ADR-0029: The desktop app is a complete management surface, co-equal with the CLI

- Status: Accepted
- Date: 2026-07-17
- Scope: the Phase 9 control-panel UI in `src/apps/desktop` (Tauri v2), its
  command surface over `chromium-bridge-core`, and how the app relates to the
  bundled host binary, the CLI, and the Phase 8 user-presence gates.

## Context

ADR-0023 planned a desktop app as the eventual primary install and management
surface; ADR-0026 proved the signing and entitlement chain that makes the
bundled host Enclave-capable. What remained was the app itself: until now,
`src/apps/desktop` was the Phase 6 signing-spike shell, and every management
task (registration, pairing, kill switch, client allowlist, audit) required a
terminal.

The design constraint that shapes everything here is the zero-trust rule from
AGENTS.md: enforcement never lives in UI code. A webview is the least
trustworthy part of this codebase; whatever it asks for must be decided,
refused, and audited by the Rust core exactly as if the CLI had asked.

## Decision

### One engine, several surfaces

The app adds no second implementation of anything. Every mutating action runs
through the same core code path the CLI uses:

- Registration writes go through `registration::Registrar` and the shared
  browser-path resolver (`browsers::resolve`), the engine behind
  `doctor --fix` and `uninstall`. The fail-closed rules (foreign manifests
  refused, unreadable paths left alone, ownership verified before deletion)
  are the engine's; the app cannot bypass them because it has no other write
  path.
- Kill-switch transitions call `kill::engage` / `kill::release`. Engaging is
  one click with no confirmation, because it only reduces capability.
  Releasing demands a `presence::PresenceAttestation`, which the app cannot
  forge (the type is only constructible inside the presence module).
- Client allowlist reads and writes go through `allowlist::load_enforced`,
  `Allowlist::pair`, and `Allowlist::revoke`, honoring the ADR-0025
  tamper-evidence latch. Anchor validation shares the CLI's
  `allowlist::resolve_anchor`, promoted to `pub` for exactly this reason: a
  malformed hash must be refused identically on every surface.
- Audit records written by app actions carry `Surface::Core`, so the trail
  always names which surface acted. The audit panel parses the on-disk trail
  with the same strict rules as `chromium-bridge audit` (version check,
  `deny_unknown_fields`); an unparsable line renders as an explicit
  unrecognized marker, never a guess.

The Tauri command layer (`src/apps/desktop/src/main.rs`) is a thin async
adapter over these calls. Its capability file allows the main window only the
app's own commands, and the webview's CSP stays `default-src 'self'` (plus
inline styles for the component library).

### Enclave operations run in the bundled host, as a subprocess

ADR-0026 gave the keychain entitlement to the bundled host only; the app
binary deliberately has none. That decision stands, and it dictates the
pairing flow: the app spawns the bundled host
(`Contents/Helpers/chromium-bridge.app/Contents/MacOS/chromium-bridge`) and
runs the real `pair` / `pair --reset` / `revoke` ceremony in that process.
The Touch ID prompt those operations raise belongs to the signed host, which
is the exact chain the 2026-07-17 proof exercised (see ADR-0026). The app
window shows the ceremony transcript verbatim and then the key fingerprint,
the same one `pair` prints, for the user to compare against the extension's
enrollment screen.

To read enrollment state without scraping human-oriented text, the host CLI
gained `enclave-status --json`: one versioned JSON object (key state,
fingerprint, public key, policy). The app refuses a report version it does
not understand. This is a deliberate, small widening of the CLI contract that
any co-equal surface can use.

In development (no .app bundle), the app falls back to the host binary
sitting next to it in `target/<profile>/`. There is no further fallback:
registering a manifest that points at a binary we cannot name would be worse
than failing.

### Presence-gated actions fail closed until Phase 8 lands

Two app actions grant capability: releasing the kill switch and adding a
trusted client. Both route through `presence::require_presence`, hardware
rung first. Phase 8 (in flight on `feat/phase8-touchid`) supplies the
LocalAuthentication provider; until this branch rebases over it, the hardware
rung reports unavailable and the only floor a GUI process can honestly claim,
the CLI's typed terminal confirmation, refuses because a GUI's stdin is not a
terminal.

So in this branch, those two buttons refuse, with an error that names the
surfaces that do work today (`chromium-bridge unkill`, `pair-client`, the
extension options page). That is the intended posture, not a gap to paper
over: claiming `Floor::ExtensionConfirm` from the app would assert a
confirmation that never happened, and inventing an app-owned click-to-confirm
floor would add exactly the soft path the Touch ID gate exists to close. The
seam is `src/apps/desktop/src/presence_seam.rs`; refused releases are audited
(`kill_release` / outcome `refused`) so an attempted silent unkill is visible
in the trail either way.

### Self-registration on first launch

On its first launch the app registers the native-messaging manifests for
every detected browser through the shared engine, reports what it wrote (and
any refusals) in the window, and leaves a marker file
(`desktop-first-run.json` in the install dir) so later launches do not write
unasked. Registration points at the bundled host. After the first run,
registration is explicit: per-browser register/repair/remove buttons, plus a
manual absolute-path `NativeMessagingHosts` directory for Chromium builds the
resolver does not know by name (the CLI's `--manifest-dir` escape hatch, same
validation).

A failed host resolution (a dev build without the host compiled) writes no
marker, so the next launch retries.

### The rest of the management surface

- The Setup page renders a copy-paste `claude mcp add chromium-bridge --
  '<host path>'` snippet, quoting the path the same way the wrapper generator
  does.
- "Install command-line tool" creates one symlink,
  `~/.local/bin/chromium-bridge`, pointing at the bundled host. Install and
  remove only ever touch a symlink whose target binary is named
  `chromium-bridge`; a regular file or any other symlink at that path is
  refused and left in place. This mirrors the registration engine's posture
  toward files we did not write, and it keeps the action reversible from the
  same page.
- The built extension is bundled into the app at
  `Contents/Resources/extension`, and the Setup page walks the user through
  `chrome://extensions` -> Load unpacked, with a reveal-in-Finder button.
  `scripts/desktop-bundle.ts` copies the extension in before the outer
  signature seals the Resources, and now also stamps the helper bundle's
  Info.plist with the workspace version (closing the version-pinning item
  ADR-0026 left open).

### Trilingual UI

The UI ships en, zh_CN, and zh_TW, English canonical, with the extension's
patterns: a language picker whose options are each rendered in their own
language (`native-language-names.ts`, never translated), "auto" following the
system locale with bare `zh` meaning Simplified. Coverage is enforced twice:
the zh bundles are typed `Record<MessageKey, string>` (a missing or extra key
is a compile error) and a vitest asserts key parity at runtime. The check-cjk
gate's allowlist now includes the desktop locale files and native-name
constants; `.typography-allow` exempts the same files, the same category as
the extension's locale exemption.

### Workspace and CI placement

The desktop crate stays a workspace member but not a default member, per the
existing policy: `cargo build/test/clippy` remain the core-and-host gate.
The UI (Vite + React 19 + Radix + Tailwind v4 + Zustand, the cloud-speech
house stack) is a bun workspace at `src/apps/desktop/ui`; its typecheck rides
`bun run typecheck` and its unit tests ride `just ci` (`desktop-ui-test`),
both platform-neutral. The Rust crate's clippy and tests run in a dedicated
macOS CI job (`desktop`, wired into all-green), because compiling Tauri needs
platform GUI toolchains. Building the crate requires the UI dist first
(tauri's `generate_context!` embeds it); `just desktop-check-rust` sequences
that locally.

Platform status, honestly: on macOS the app covers the full management
surface, with two actions (kill release, add client) refusing until Phase 8
supplies the hardware presence rung; see the seam section above. The Rust
command layer compiles for Linux and Windows (the registration and
kill/audit paths are cross-platform in core), but the bundled-host layout,
the Enclave ceremony, and the CLI symlink are macOS-shaped; Linux needs a
WebKitGTK toolchain, a stable `~/.local/lib` host install path (the AppImage
FUSE-mount issue from the plan), and its own presence floor; Windows needs
WebView2 packaging and the registry-side verification ADR-0015 already
flags. Those land with their platforms, not speculatively here.

### The app binary keeps its application-identifier entitlement

ADR-0026 left open whether the outer app needs `application-identifier`.
It keeps it: the embedded provisioning profile authorizes the pairing of
team, identifier, and entitlements for the bundle, and dropping the app-side
identifier buys nothing while making the app and host signatures asymmetric
in a way the check script would have to special-case. The check script
continues to assert the exact entitlement sets of both binaries.

## Consequences

- A user on macOS can install, register, pair, revoke, audit, and engage the
  kill switch from the window alone. The last two terminal dependencies
  (releasing the kill switch, adding a client) are the presence-gated acts,
  and they move in-window when Phase 8's Touch ID provider lands; until then
  the app refuses them with guidance. Everything the app does lands in the
  same audit trail and the same enforcement paths as the CLI.
- The CLI loses nothing and remains complete; `doctor --fix` and the app's
  registration converge on identical bytes, so mixing surfaces cannot fork
  state.
- Until Phase 8 lands, the app's kill-release and add-client buttons refuse
  with guidance. After the rebase they acquire Touch ID with no change to
  this crate beyond the seam file (or a swap to Phase 8's dedicated gated
  pairing API, if its shape differs).
- The host CLI's `enclave-status --json` is now a stable machine contract;
  changing its shape requires a version bump and a consumer update.
