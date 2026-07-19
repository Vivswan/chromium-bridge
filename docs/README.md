# chromium-bridge documentation

This directory is the **single source of truth** for the chromium-bridge
project. Code comments answer "what does this code do"; this directory answers
"why it is done this way, what it must do, and what the constraints are".

## Doc map

| Doc | Contents | Audience |
|------|------|------|
| [quickstart.md](./quickstart.md) | Install and first use: the desktop app path and the CLI path ([Simplified](./quickstart.zh_CN.md) / [Traditional Chinese](./quickstart.zh_TW.md)) | Users (start here) |
| [requirements.md](./requirements.md) | Requirements: goals, user stories, functional/non-functional requirements, scope boundaries | Everyone |
| [architecture.md](./architecture.md) | Architecture: components, data flow, protocols, security model, key constraints, technology choices | Implementers, reviewers |
| [cli.md](./cli.md) | The full CLI: doctor/--fix/uninstall, enrollment, trusted clients, kill switch, audit, troubleshooting | Users, troubleshooters |
| [desktop-app.md](./desktop-app.md) | The desktop app: what it manages, building it, what to verify by hand | Users, maintainers |
| [operations.md](./operations.md) | Operations: the wire modes, logging/audit, the runtime directory, reconnect, kill-state recovery | Users, operators |
| [compatibility.md](./compatibility.md) | Compatibility: the three kinds of version, the internal protocol version, the capability/version handshake (contract status) | Implementers, reviewers |
| [release.md](./release.md) | Releasing: tag-driven pipeline, prebuilt archives + checksums + provenance, SBOM | Releasers, reviewers |
| [privacy-policy.md](./privacy-policy.md) | The extension's privacy policy ([Simplified](./privacy-policy.zh_CN.md) / [Traditional Chinese](./privacy-policy.zh_TW.md)) | Users, store review |
| [chrome-web-store.md](./chrome-web-store.md) | Decision checklist for publishing to the Chrome Web Store: pinned-ID migration, review risks, prerequisites | Maintainers (decision) |
| [wsl.md](./wsl.md) | The two WSL modes: Windows Chrome interop and WSLg | Users on WSL |
| [security/threat-model.md](./security/threat-model.md) | Assets, actors, threats, mitigations, residual risks | Reviewers, reporters |
| [security/trust-boundaries.md](./security/trust-boundaries.md) | Each protocol hop and how it is enforced | Reviewers |
| [security/tool-risk-matrix.md](./security/tool-risk-matrix.md) | Every tool's blast radius and protections | Reviewers |
| [security/incident-response.md](./security/incident-response.md) | Security incident response runbook: reporting, triage, mitigation, disclosure | Maintainers, reporters |
| [adr/](./adr/) | Architecture Decision Records (ADRs): a traceable record of every "why was this chosen" | Reviewers, future changers |

> The single source of truth for cross-process contracts (tool catalogue,
> error taxonomy, capabilities, protocol version, identity, wire envelopes)
> is the Rust core; the TS side is generated from it (`just gen`). See
> [architecture.md section 11](./architecture.md#11-protocol-boundary-contracts-error-taxonomy-and-handshake)
> and [ADR-0028](./adr/0028-contracts-dissolved-into-rust-core.md).

> The **development process** (branch/commit/sync/merge rules) is in the
> root-level [`CONTRIBUTING.md`](../CONTRIBUTING.md); the quick-reference
> entry point for agents is [`AGENTS.md`](../AGENTS.md). The build/test
> toolchain is in [development.md](./development.md).

> `src/apps/web/` holds a minimal Astro site (`just web-build`) that renders
> these markdown docs and their translations; the markdown stays the single
> source. Cross-doc links on the rendered site still point at `.md` paths
> (a link rewrite is a tracked follow-up); navigate from its index page.

## How to read

- **First time using the project** -> `quickstart.md`
- **First time learning the project** -> `requirements.md` -> `architecture.md`
- **Changing a design decision** -> read the corresponding ADR first, see the trade-offs made at the time, then decide whether to overturn it
- **Changing anything security-relevant** -> `../SECURITY.md` (the review bar) and `security/`

## ADR index

An ADR (Architecture Decision Record) records a decision where **multiple
reasonable options existed and one was chosen**. Uncontroversial routine
choices do not get an ADR.

| # | Title | Status |
|---|------|------|
| [0001](./adr/0001-use-rust-single-binary.md) | Rust single binary with subcommand dispatch | Accepted |
| [0002](./adr/0002-three-process-architecture-localhost-tcp.md) | Three-process architecture with localhost TCP bridging | Accepted; transport superseded by ADR-0019/0020/0024 |
| [0003](./adr/0003-content-script-snapshot-vs-chrome-debugger.md) | Snapshot via content script, not chrome.debugger | Accepted |
| [0004](./adr/0004-allowlist-with-optional-host-permissions.md) | Allowlist with on-demand optional host permissions | Accepted |
| [0005](./adr/0005-page-eval-disabled-by-default.md) | page_eval disabled by default | Superseded by #0008 |
| [0006](./adr/0006-toast-confirmation-for-high-risk.md) | In-page Toast for high-risk actions, with a short confirmation-free window | Accepted; surface superseded by #0027 |
| [0007](./adr/0007-mcp-protocol-version-2025-06-18.md) | Pin the MCP protocol version to 2025-06-18 | Accepted |
| [0008](./adr/0008-page-eval-confirmation-channel.md) | page_eval high-risk confirmation channel | Accepted |
| [0009](./adr/0009-page-snapshot-precise-debugger.md) | page_snapshot_precise takes the authoritative a11y tree via chrome.debugger | Accepted |
| [0010](./adr/0010-cookie-storage-readonly.md) | Read-only Cookie/Storage access | Accepted |
| [0011](./adr/0011-options-page-for-settings.md) | Settings managed through a dedicated Options page | Accepted |
| [0012](./adr/0012-typescript-esbuild-extension-build.md) | TypeScript + esbuild extension build | Superseded by #0027 (WXT) |
| [0013](./adr/0013-ci-and-toolchain.md) | CI and toolchain | Accepted; revised by #0023 (bun/Biome/just) |
| [0014](./adr/0014-leveled-logging.md) | Leveled stderr logging + typed errors | Accepted |
| [0015](./adr/0015-windows-support.md) | Windows support | Accepted (best-effort; see SECURITY.md) |
| [0016](./adr/0016-linux-wsl-support.md) | Linux and WSL support | Accepted |
| [0017](./adr/0017-cdp-mode-all-ops.md) | CDP mode (all page operations optionally via chrome.debugger) | Accepted |
| [0018](./adr/0018-tab-workspace-group.md) | AI tabs go into a "Browser Bridge" tab group (workspace) | Accepted |
| [0019](./adr/0019-authenticated-ipc.md) | Authenticated IPC (Unix-domain socket + HMAC) | Accepted |
| [0020](./adr/0020-kernel-attested-peer-identity.md) | Kernel-attested peer identity | Accepted |
| [0021](./adr/0021-enrollment-ceremony.md) | The enrollment ceremony (Secure Enclave key + pin) | Accepted |
| [0022](./adr/0022-multi-browser-label-routing.md) | Multi-browser label routing | Accepted |
| [0023](./adr/0023-workspace-monorepo-tauri-app.md) | Workspace monorepo, Tauri app, and the rebrand | Accepted |
| [0024](./adr/0024-multi-client-attested-pairing-and-broker.md) | Multi-client attested pairing and the ref-counted broker | Accepted |
| [0025](./adr/0025-any-side-revocation-epoch.md) | Any-side revocation epoch | Accepted |
| [0026](./adr/0026-tauri-signing-and-entitlement-chain.md) | Tauri signing and the entitlement chain | Accepted |
| [0027](./adr/0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) | Extension rehaul: WXT, off-DOM confirmations, i18n | Accepted |
| [0028](./adr/0028-contracts-dissolved-into-rust-core.md) | Contracts dissolved into the Rust core | Accepted |
| [0029](./adr/0029-desktop-app-management-surface.md) | The desktop app as a management surface | Accepted |
| [0030](./adr/0030-global-kill-switch-and-audit.md) | Global kill switch and the audit trail | Accepted |
| [0031](./adr/0031-touch-id-confirmations-and-presence-grants.md) | Touch ID confirmations and presence-gated grants | Accepted |
| [0032](./adr/0032-host-owned-policy-settings.md) | Host-owned policy settings and paired language sync | Accepted |

## ADR writing conventions

When adding an ADR:
- File name: `NNNN-kebab-case-title.md`, numbered after the current maximum
- Status: Accepted / Superseded by #NNNN / Deprecated
- Required sections: context, decision, alternatives considered, consequences
- One decision per ADR; do not mix

A superseded ADR is **not deleted**: change its status to
`Superseded by #NNNN` with a link, and keep the history.
