# Chromium Bridge

Chromium Bridge lets an MCP client drive the Chromium browser you are already signed into, through a browser extension and a native-messaging host, with no debug port. Code is the source of truth: where a page states a behaviour, the file that owns it is the authority. The security pages say what the bridge promises and where it stops; the rest say how to use, run, and change it.

## I want to...

| Goal | Read |
|---|---|
| Install the binary and the extension, and run a first tool call | [Quickstart: the CLI](quickstart.md#the-cli-macos-linux-windows) |
| Check that the install is healthy, or read "server not reachable" | [CLI: doctor and status](cli.md#doctor--status-read-only-self-check) |
| Register the native-messaging host with a browser, or remove it | [CLI: doctor --fix and uninstall](cli.md#doctor---fix--uninstall-native-messaging-registration) |
| Admit an MCP client, or revoke one | [CLI: trusted clients](cli.md#trusted-clients-pair-client--revoke-client--list-clients) |
| Halt everything now, and release the halt later | [CLI: kill switch](cli.md#kill-switch-kill--unkill) |
| Change what tools are allowed to do | [CLI: host-owned policy](cli.md#host-owned-policy-policy) |
| Read the logs and the audit trail | [CLI: logging and audit](cli.md#logging-and-audit-bb_log--bb_log_format) |
| Recover from an unreadable kill record, or a dropped native-host connection | [Operations](operations.md) |
| Use the bridge from WSL | [WSL](wsl.md) |
| Know what the bridge promises an attacker cannot do, and where that stops | [The security bar](security/security-bar.md#the-bar-in-one-line) |
| See what each tool can reach and which confirmation it triggers | [Tool risk matrix](security/tool-risk-matrix.md) |
| Report a security issue | [Incident response: reporting](security/incident-response.md#reporting-channel) |
| Understand why a security decision was taken before changing it | [Security rationale](security/rationale.md) |
| Know what the extension collects and stores | [Privacy policy](privacy-policy.md) |
| See how the processes connect and what crosses each hop | [Architecture: overview](architecture.md#1-architecture-overview) |
| Find the cross-process contracts (tool catalogue, error taxonomy, capabilities, protocol version, identity, wire envelopes) the Rust core owns and `moon run gen` emits as TypeScript | [Architecture: protocol boundary contracts](architecture.md#11-protocol-boundary-contracts-error-taxonomy-and-handshake) |
| Learn the project from the problem it solves before its design | [Requirements](requirements.md) |
| Change something security-relevant | [Review bar](../.github/SECURITY.md) |
| Set up the toolchain and run the gate | [Development: moon](development.md#moon-the-canonical-command-interface) |
| Run the browser suites against an isolated Chrome, never your own | [Tests](../tests/README.md) |
| Add a tool | [Contributing: adding a tool](../CONTRIBUTING.md#adding-a-tool) |
| Cut a release | [Releasing](release.md#trigger-merge-the-release-pr) |

## The pages

### Using it

1. [Quickstart](quickstart.md): install, first use, recommended hardening, uninstalling.
2. [CLI](cli.md): doctor, registration, enrollment, trusted clients, kill switch, policy, logging and audit, and the troubleshooting each answers.
3. [Operations](operations.md): the two wire modes, logging and audit, the runtime directory, reconnect, kill-state recovery.
4. [WSL](wsl.md): the two WSL modes, Windows Chrome interop and WSLg, and the rule against mixing them.
5. [Privacy policy](privacy-policy.md): what the extension can access, what it stores, and what it never sends.

### Security

6. [Security bar](security/security-bar.md): the one-line promise, the attackers it answers, where it stops, per OS.
7. [Threat model](security/threat-model.md): assets, actors, threats, mitigations, residual risks.
8. [Trust boundaries](security/trust-boundaries.md): each protocol hop and the mechanism that enforces it.
9. [Tool risk matrix](security/tool-risk-matrix.md): every tool's blast radius and protections.
10. [Incident response](security/incident-response.md): reporting, triage, mitigation, disclosure.
11. [Security rationale](security/rationale.md): why each decision was taken and what it rejected.
12. [Review bar](../.github/SECURITY.md): the surfaces that get extra review, the defaults that fail safe, and what to read before a security-relevant change.

### Reference

13. [Architecture](architecture.md): components, protocols, data flows, the security model, key constraints, technology choices, and the contracts the Rust core generates.
14. [Compatibility](compatibility.md): the three kinds of version, the internal protocol version, and the capability and version handshake with its contract status.
15. [Requirements](requirements.md): goals, user stories, functional and non-functional requirements, scope boundaries.

### Contributing

16. [Development](development.md): toolchain, layout, moon tasks, testing, the container, fuzzing.
17. [Releasing](release.md): the release-please pipeline, prebuilt archives with checksums and provenance, SBOM, SemVer rules.
18. [Chrome Web Store](chrome-web-store.md): the publishing decision checklist, the pinned-ID trap, review risks, prerequisites.
19. [CONTRIBUTING](../CONTRIBUTING.md): the development process, from branch, commit, and sync rules to the squash-merge.
20. [Tests](../tests/README.md): the suites, and the rule that browser tests run only against an isolated Chrome, never your daily browser.
