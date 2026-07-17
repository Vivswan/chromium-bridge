# browser-bridge documentation

This directory is the **single source of truth** for the browser-bridge
project. Code comments answer "what does this code do"; this directory answers
"why it is done this way, what it must do, and what the constraints are".

## Doc map

| Doc | Contents | Audience |
|------|------|------|
| [requirements.md](./requirements.md) | Requirements: goals, user stories, functional/non-functional requirements, scope boundaries, phase plan | Everyone (read this first) |
| [architecture.md](./architecture.md) | Architecture: components, data flow, protocols, security model, key constraints, technology choices | Implementers, reviewers |
| [cli.md](./cli.md) | CLI subcommands and troubleshooting: the `doctor`/`status` read-only self-check, how to interpret "server not reachable" | Users, troubleshooters |
| [operations.md](./operations.md) | Operations: the two binary modes, `doctor`/`status`, `BB_LOG`/audit, the lock file, native host reconnect | Users, operators |
| [compatibility.md](./compatibility.md) | Compatibility: the three kinds of version, the internal protocol version, the capability/version handshake (contract status) | Implementers, reviewers |
| [release.md](./release.md) | Releasing: tag-driven pipeline, prebuilt tarballs + checksums, dual-mode `install.sh`, SBOM | Releasers, reviewers |
| [chrome-web-store.md](./chrome-web-store.md) | Decision checklist for publishing to the Chrome Web Store: pinned-ID migration, review risks, prerequisites | Maintainers (decision) |
| [security/incident-response.md](./security/incident-response.md) | Security incident response runbook: reporting, triage, mitigation (disable tools / revoke allowlist / kill switch), disclosure | Maintainers, reporters |
| [adr/](./adr/) | Architecture Decision Records (ADRs): a traceable record of every "why was this chosen" | Reviewers, future changers |

> The single source of truth for cross-process contracts (tool catalogue,
> error taxonomy, capabilities, protocol version) is
> [`contracts/`](../contracts/README.md).

> The **development process** (branch/commit/sync/merge rules) is in the
> root-level [`CONTRIBUTING.md`](../CONTRIBUTING.md); the quick-reference
> entry point for agents is [`AGENTS.md`](../AGENTS.md). The build/test
> toolchain is in [development.md](./development.md).

## How to read

- **First time learning the project** -> `requirements.md` -> `architecture.md`
- **Changing a design decision** -> read the corresponding ADR first, see the trade-offs made at the time, then decide whether to overturn it
- **Adding a new feature** -> check the "scope boundaries" in `requirements.md` first to confirm it is in scope for v0.1

## ADR index

An ADR (Architecture Decision Record) records a decision where **multiple
reasonable options existed and one was chosen**. Uncontroversial routine
choices do not get an ADR.

| # | Title | Status |
|---|------|------|
| [0001](./adr/0001-use-rust-single-binary.md) | Rust single binary with subcommand dispatch | Accepted |
| [0002](./adr/0002-three-process-architecture-localhost-tcp.md) | Three-process architecture with localhost TCP bridging | Accepted; superseded in part by ADR-0019 |
| [0003](./adr/0003-content-script-snapshot-vs-chrome-debugger.md) | Snapshot via content script, not chrome.debugger | Accepted |
| [0004](./adr/0004-allowlist-with-optional-host-permissions.md) | Allowlist with on-demand optional host permissions | Accepted |
| [0005](./adr/0005-page-eval-disabled-by-default.md) | page_eval disabled by default | Superseded by #0008 |
| [0006](./adr/0006-toast-confirmation-for-high-risk.md) | In-page Toast for high-risk actions, with a short confirmation-free window | Accepted |
| [0007](./adr/0007-mcp-protocol-version-2025-06-18.md) | Pin the MCP protocol version to 2025-06-18 | Accepted |
| [0008](./adr/0008-page-eval-confirmation-channel.md) | page_eval high-risk confirmation channel | Accepted |
| [0009](./adr/0009-page-snapshot-precise-debugger.md) | page_snapshot_precise takes the authoritative a11y tree via chrome.debugger | Accepted |
| [0010](./adr/0010-cookie-storage-readonly.md) | Read-only Cookie/Storage access | Accepted |
| [0011](./adr/0011-options-page-for-settings.md) | Settings managed through a dedicated Options page | Accepted |
| [0017](./adr/0017-cdp-mode-all-ops.md) | CDP mode (all page operations optionally via chrome.debugger) | Accepted |
| [0018](./adr/0018-tab-workspace-group.md) | AI tabs go into a "Browser Bridge" tab group (workspace) | Accepted |

## ADR writing conventions

When adding an ADR:
- File name: `NNNN-kebab-case-title.md`, numbered after the current maximum
- Status: Accepted / Superseded by #NNNN / Deprecated
- Required sections: context, decision, alternatives considered, consequences
- One decision per ADR; do not mix

A superseded ADR is **not deleted**: change its status to
`Superseded by #NNNN` with a link, and keep the history.
