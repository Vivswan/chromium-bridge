# Architecture decision records

One record per decision that shaped the bridge, numbered in the order it was taken. A record is never rewritten; a later record supersedes it and says so in its status.

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](./0001-use-rust-single-binary.md) | Rust single binary with subcommand dispatch | Accepted (the dependency-list part is amended by [ADR-0014](./0014-leveled-logging.md)) |
| [0002](./0002-three-process-architecture-localhost-tcp.md) | Three-process architecture with localhost TCP bridging | Accepted; superseded in part by ADR-0019 (localhost TCP -> 0600 Unix domain socket); the three-process architecture still holds |
| [0003](./0003-content-script-snapshot-vs-chrome-debugger.md) | Snapshot via content script, not chrome.debugger | Accepted |
| [0004](./0004-allowlist-with-optional-host-permissions.md) | Allowlist with on-demand optional host permissions | Accepted |
| [0005](./0005-page-eval-disabled-by-default.md) | page_eval disabled by default | Superseded by [ADR-0008](./0008-page-eval-confirmation-channel.md) |
| [0006](./0006-toast-confirmation-for-high-risk.md) | In-page Toast for high-risk actions, with a short confirmation-free window | Superseded by [ADR-0027](./0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) (the confirmation surface moves off the page-reachable DOM into an extension-owned window; the risk tiering and the click grace window it introduced stand and moved into `confirm/gate.ts`). Phase 8 completes the supersession for `page_eval`/`page_upload` when their approval becomes the Secure Enclave tap. |
| [0007](./0007-mcp-protocol-version-2025-06-18.md) | Pin the MCP protocol version to 2025-06-18 | Superseded by [ADR-0034](0034-mcp-2026-07-28-stateless.md) |
| [0008](./0008-page-eval-confirmation-channel.md) | page_eval high-risk confirmation channel | Amended by [ADR-0027](./0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) (page_eval still confirms on every call, but the confirmation renders on the extension-owned window instead of an in-page toast). Phase 8 supersedes the channel entirely for page_eval by routing approval through the host Secure Enclave. |
| [0009](./0009-page-snapshot-precise-debugger.md) | page_snapshot_precise takes the authoritative a11y tree via chrome.debugger | Accepted |
| [0010](./0010-cookie-storage-readonly.md) | Read-only Cookie/Storage access | Accepted |
| [0011](./0011-options-page-for-settings.md) | Settings managed through a dedicated Options page | Accepted |
| [0012](./0012-typescript-esbuild-extension-build.md) | Extension written in TypeScript, bundled with esbuild into dist/ | Accepted |
| [0013](./0013-ci-and-toolchain.md) | Unified toolchain and CI (task entry point + GitHub Actions + single version source) | Accepted (the task-entry-point part was amended twice: justfile -> Makefile-only upstream, then moon after the ADR-0023 rebuild) |
| [0014](./0014-leveled-logging.md) | Leveled logging (BB_LOG) and typed errors with thiserror | Accepted |
| [0015](./0015-windows-support.md) | Windows local run and install support | Accepted |
| [0016](./0016-linux-wsl-support.md) | Linux and WSL dual run modes | Accepted |
| [0017](./0017-cdp-mode-all-ops.md) | CDP mode (all page operations optionally via chrome.debugger) | Accepted |
| [0018](./0018-tab-workspace-group.md) | AI tabs go into a "Browser Bridge" tab group (workspace) | Accepted |
| [0019](./0019-authenticated-ipc.md) | Authenticated, port-less bridge IPC (UDS + peer-UID + HMAC) | Accepted |
| [0020](./0020-kernel-attested-peer-identity.md) | Kernel-attested peer executable identity for the bridge | Accepted |
| [0021](./0021-enrollment-ceremony.md) | Enrollment ceremony with a Secure Enclave key | Accepted |
| [0022](./0022-multi-browser-label-routing.md) | Multiple browser connections, keyed by a label in the authenticated handshake | Accepted |
| [0023](./0023-workspace-monorepo-tauri-app.md) | Workspace monorepo, Tauri v2 control panel, and the chromium-bridge rebrand (umbrella) | Accepted |
| [0024](./0024-multi-client-attested-pairing-and-broker.md) | Multi-client attested pairing and the ref-counted broker | Accepted |
| [0025](./0025-any-side-revocation-epoch.md) | Any-side revocation epoch | Accepted |
| [0026](./0026-tauri-signing-and-entitlement-chain.md) | Signing the bundled host for Secure Enclave access (Tauri v2 spike) | Accepted (Touch ID proof passed on 2026-07-17, see "The Touch ID proof") |
| [0027](./0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) | Extension rehaul: off-DOM confirmation surface, WXT, and runtime i18n | Accepted |
| [0028](./0028-contracts-dissolved-into-rust-core.md) | Contracts dissolved into the Rust core | Accepted |
| [0029](./0029-desktop-app-management-surface.md) | The desktop app is a complete management surface, co-equal with the CLI | Accepted |
| [0030](./0030-global-kill-switch-and-audit.md) | Global kill switch and audit surfaces | Accepted |
| [0031](./0031-touch-id-confirmations-and-presence-grants.md) | Touch ID confirmations and presence-gated capability grants | Accepted |
| [0032](./0032-host-owned-policy-settings.md) | Host-owned policy settings and paired language sync | Accepted |
| [0033](./0033-adopt-repo-platform-fleet-template.md) | Full adoption of the repo-platform fleet template | Accepted |
| [0034](./0034-mcp-2026-07-28-stateless.md) | MCP 2026-07-28 (stateless) on the official rmcp SDK | Accepted |
| [0035](./0035-automated-supply-chain-review.md) | Automated supply-chain review replaces the cargo-vet gate | Accepted |
