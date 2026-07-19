# ADR-0029: The desktop app is a complete management surface, co-equal with the CLI

- Status: Accepted
- Date: 2026-07-17 (amended 2026-07-18: first launch no longer
  self-registers; see "First launch detects; the user connects")
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

### Presence-gated actions: dialog-first, hardware-first

Two app actions grant capability: releasing the kill switch and adding a
trusted client. Both are gated on user presence (ADR-0031). Pairing goes
through `allowlist::pair_client_with_presence(name, anchor, Surface::Core,
Floor::AppConfirm)`, the one entry point every surface uses: it validates
the name before any prompt, runs the presence ladder, audits both outcomes
with the rung that decided, and returns the `PresencePath` that authorized
it. Unkill goes through `presence::require_presence(reason,
Floor::AppConfirm)` then `kill::release`. On an enrolled Mac the ladder's
hardware rung raises the real Touch ID sheet (per-action Secure Enclave
signing); `Floor::AppConfirm` is reached only when hardware is genuinely
unavailable, never on a hardware refusal, and it succeeds on the assertion
that the app already showed its own explicit modal confirmation.

That assertion is load-bearing, so the UI is built dialog-first: both
buttons open an explicit confirm modal (with a synchronous single-flight
guard), and only the modal's confirm handler invokes the presence-gated
command. The command's result carries the presence path, and the UI names
which proof authorized the act (Touch ID, or the in-app confirmation on a
no-hardware machine). `AppConfirm` on such a machine is an intent floor,
not an unspoofable hardware proof - the same residual class as the CLI's
typed-terminal floor, named in the `Floor` docs rather than implied
covered. Engaging the kill switch and revoking (a client, or the
enrollment) stay one-click on purpose: they only reduce capability, and
friction-free revocation is the security posture. Refused releases and
refused pairings are audited (outcome `refused` with the presence error),
so an attempted silent unkill or enrollment is visible in the trail.

The seam is `src/apps/desktop/src/presence_seam.rs`; its `APP_FLOOR`
constant and the dialog-first obligation are the only presence knowledge
this crate holds.

### First launch detects; the user connects (amended 2026-07-18)

As first shipped, the app registered the native-messaging manifests for
every detected browser on its first launch. That was withdrawn the next
day. A manifest write into a browser's configuration directory grants this
software a path into that browser, and the project's consent rules (the
zero-trust section of AGENTS.md; confirmations are a feature) require such
a grant to be the user's explicit choice, not a side effect of opening the
app. The rest of this ADR already insists every capability grant is
user-initiated; startup-time registration was the one exception, and it is
gone.

Now the first launch only detects. The app resolves the known browsers,
names the detected ones on the Overview first-run card, and writes nothing
into any browser's configuration. The user connects browsers one at a time
on the Browsers page, or clicks the card's explicit "Connect all detected
browsers" button. Both paths run the same shared engine command; only the
trigger changed, from app startup to a user click. The Browsers page
offers an action only where one exists: a healthy registration shows
"Connected" with no button, a missing one shows Connect, and a wrong one
(stale, foreign, unreadable) shows Repair.

The marker file (`desktop-first-run.json` in the install dir) survives
with a narrower meaning: it records that a launch claimed the first-run
card, so later launches do not reopen it (claimed, not provably rendered;
a crash between claim and paint forfeits the card, and the Browsers page
carries the same information). It is still claimed single-flight with
`create_new`, the install dir is verified to be a real directory before
the write (a planted symlink cannot redirect it; hardening against
redirection, not a privilege boundary), and it remains app state rather
than a registration artifact, so `uninstall` semantics are untouched.
Markers written by the withdrawn behavior read the same way, since only
existence is checked.

Registration after the first run is unchanged: per-browser buttons, plus a
manual absolute-path `NativeMessagingHosts` directory for Chromium builds
the resolver does not know by name (the CLI's `--manifest-dir` escape
hatch, same validation).

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
`bun run typecheck` and its unit tests ride `just ci` (`test-app-ui`),
both platform-neutral. The Rust crate's clippy and tests run in a dedicated
macOS CI job (`desktop`, wired into all-green), because compiling Tauri needs
platform GUI toolchains. Building the crate requires the UI dist first
(tauri's `generate_context!` embeds it); `just check-app-rust` sequences
that locally.

Platform status, honestly: on macOS the app covers the full management
surface, including the two presence-gated acts (kill release, add client)
under Touch ID on an enrolled Mac; see the seam section above. The Rust
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

- A user on macOS manages the whole bridge from the window: install,
  register, pair, revoke, audit, engage the kill switch, and - behind the
  confirm dialog plus the presence gate - release it and add trusted
  clients. Everything the app does lands in the same audit trail and the
  same enforcement paths as the CLI.
- The CLI loses nothing and remains complete; `doctor --fix` and the app's
  registration converge on identical bytes, so mixing surfaces cannot fork
  state.
- The host CLI's `enclave-status --json` is now a stable machine contract;
  changing its shape requires a version bump and a consumer update.
