# chromium-bridge

This directory is the **single source of truth** for the chromium-bridge project. Code comments answer "what does this code do"; this directory answers "why it is done this way, what it must do, and what the constraints are".

## Doc map

| Doc | Contents | Audience |
|------|------|------|
| [quickstart.md](./quickstart.md) | Install and first use: the CLI path ([Simplified](./quickstart.zh_CN.md) / [Traditional Chinese](./quickstart.zh_TW.md)) | Users (start here) |
| [requirements.md](./requirements.md) | Requirements: goals, user stories, functional/non-functional requirements, scope boundaries | Everyone |
| [architecture.md](./architecture.md) | Architecture: components, data flow, protocols, security model, key constraints, technology choices | Implementers, reviewers |
| [cli.md](./cli.md) | The full CLI: doctor/--fix/uninstall, enrollment, trusted clients, kill switch, audit, troubleshooting | Users, troubleshooters |
| [operations.md](./operations.md) | Operations: the wire modes, logging/audit, the runtime directory, reconnect, kill-state recovery | Users, operators |
| [compatibility.md](./compatibility.md) | Compatibility: the three kinds of version, the internal protocol version, the capability/version handshake (contract status) | Implementers, reviewers |
| [release.md](./release.md) | Releasing: the release-please pipeline, prebuilt archives + checksums + provenance, SBOM | Releasers, reviewers |
| [privacy-policy.md](./privacy-policy.md) | The extension's privacy policy ([Simplified](./privacy-policy.zh_CN.md) / [Traditional Chinese](./privacy-policy.zh_TW.md)) | Users, store review |
| [chrome-web-store.md](./chrome-web-store.md) | Decision checklist for publishing to the Chrome Web Store: pinned-ID migration, review risks, prerequisites | Maintainers (decision) |
| [wsl.md](./wsl.md) | The two WSL modes: Windows Chrome interop and WSLg | Users on WSL |
| [security/security-bar.md](./security/security-bar.md) | The security bar: the one-line promise, the attackers it answers, where it stops, the per-OS status | Everyone (read first) |
| [security/threat-model.md](./security/threat-model.md) | Assets, actors, threats, mitigations, residual risks | Reviewers, reporters |
| [security/trust-boundaries.md](./security/trust-boundaries.md) | Each protocol hop and how it is enforced | Reviewers |
| [security/tool-risk-matrix.md](./security/tool-risk-matrix.md) | Every tool's blast radius and protections | Reviewers |
| [security/incident-response.md](./security/incident-response.md) | Security incident response runbook: reporting, triage, mitigation, disclosure | Maintainers, reporters |
| [security/rationale.md](./security/rationale.md) | Why each security decision was taken, and what it rejected | Reviewers, future changers |

> The single source of truth for cross-process contracts (tool catalogue, error taxonomy, capabilities, protocol version, identity, wire envelopes) is the Rust core; the TS side is generated from it (`moon run gen`). See [architecture.md section 11](./architecture.md#11-protocol-boundary-contracts-error-taxonomy-and-handshake).

> The **development process** (branch/commit/sync/merge rules) is in the root-level [`CONTRIBUTING.md`](../CONTRIBUTING.md); the quick-reference entry point for agents is [`AGENTS.md`](../AGENTS.md). The build/test toolchain is in [development.md](./development.md).

> `src/apps/web/` holds a minimal Astro site (`moon run web:build`) that renders these markdown docs and their translations; the markdown stays the single source. Cross-doc links on the rendered site still point at `.md` paths (a link rewrite is a tracked follow-up); navigate from its index page.

## How to read

- **First time using the project** -> `quickstart.md`
- **First time learning the project** -> `requirements.md` -> `architecture.md`
- **Changing a design decision** -> for a security boundary, read its row in `security/rationale.md`; for anything else, read the PR that landed it (`git log -S`, then the linked issue); then decide whether to overturn it
- **Changing anything security-relevant** -> `../.github/SECURITY.md` (the review bar) and `security/`
