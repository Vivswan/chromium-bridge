# Incident response runbook

How a suspected breach of a boundary is reported, graded, contained, fixed, and disclosed, sized for a single-maintainer project. The assets and the boundaries are the [security page's](../security.md); the invariants a fix restores are the [ledger's](trust-boundaries.md#invariants-that-must-not-regress).

## What counts as a security incident

A compromise, or suspected compromise, of an asset the [security page](../security.md#what-is-at-stake-and-who-is-trusted) protects. For example:

- a page operation executed on an unauthorized origin, bypassing the site allowlist or the confirmation prompt;
- cookies, storage, page content, or eval return values leaked past masking;
- the bridge socket accepted an unauthenticated local peer, or the host manifest's `allowed_origins` was modified;
- the kill switch released, or a policy relaxed, without a presence proof;
- `page_eval` or its confirmation channel abused with irreversible consequences.

Not incidents: anything requiring the machine to be compromised first, or a malicious MCP client the user paired themselves (trusted by design, per the [scope](../../.github/SECURITY.md#scope)).

## Reporting channel

**Do not open a public issue for a security problem.** The private channel, what a useful report carries, and what to expect back are the [security policy's](../../.github/SECURITY.md#reporting-a-vulnerability).

## Triage

Grade a report with four questions; they track the blast radius in the [tool risk matrix](tool-risk-matrix.md):

1. **Which boundary is crossed?** Boundaries 1 through 4 in the [ledger](trust-boundaries.md); boundary 4, the page boundary, is the most critical.
2. **What can be read or changed?** Does it reach credentials (cookie or storage tokens)? Are there write or irreversible consequences?
3. **How strong are the preconditions?** Does it require the user to have authorized an origin, installed the extension, or a local same-UID process?
4. **Is it reproducible?** Is there a proof of concept?

The answers decide between "mitigate now" and "schedule a fix". Credential leakage and allowlist or confirmation bypasses are the highest priority.

## Immediate mitigation (user side, no code change needed)

Users can shrink the blast radius themselves before a patch is ready:

1. **Engage the kill switch:** `genkan kill`, or the extension's options page. Every tool call is refused and every browser connection is severed within about a second; the [CLI page](../cli.md#kill-switch-kill--unkill) owns the command and its release.
2. **Disable a single tool:** `genkan policy restrict --disabled-tools <list>` adds it to the host policy's `disabledTools`. The flag states the whole comma-separated disabled list, so keep the tools already in it. The write is free (no presence prompt) because a restriction only removes capability.
   - The host then refuses the tool with the stable `TOOL_DISABLED` code from [`ERROR_SPECS`](../../src/packages/core/src/error.rs) before any bridge traffic, and the extension enforces the pushed policy at its own boundary.
   - Disable a high-risk tool such as `page_eval` first. Re-enabling it later is a relaxation and costs one signed policy write behind the terminal confirmation, by design ([the CLI page](../cli.md#host-owned-policy-policy)).
3. **Revoke the allowlist, or turn off all-sites:** in the options page or the popup, remove the authorization for the affected origins and confirm `allowAllSites` is off. Removing an authorization also revokes that origin's host permission.
4. **Stop the extension:** disable or remove it at `chrome://extensions`. The native host gets EOF on stdin and exits, which severs the bridge; end the MCP client session too so the MCP server exits, and confirm with `doctor` ([the CLI page](../cli.md#doctor--status-read-only-self-check)).
5. **Uninstall the host manifest:** `genkan uninstall` removes the native-messaging registration, after which Chrome can no longer spawn the host ([the CLI page](../cli.md#doctor---fix--uninstall-native-messaging-registration)).

## Fix and verification

- Locate the [invariant](trust-boundaries.md#invariants-that-must-not-regress) that was crossed.
- The fix goes through the [review bar](../../.github/SECURITY.md#security-relevant-changes-review-bar): the [security-change checklist](../../.github/ISSUE_TEMPLATE/security-change.yml), the [tool risk matrix](tool-risk-matrix.md), and the [ledger](trust-boundaries.md) if a boundary changed.
- A negative security test proving the boundary holds again is mandatory; positive cases alone are not enough.

## Release and disclosure

- Tag and release the fix per the [release page](../release.md). Pre-1.0 only the latest release is supported ([supported versions](../../.github/SECURITY.md#supported-versions)), and security fixes ship as a new patch or minor.
- Coordinate disclosure through a GitHub Security Advisory: give the reporter a reasonable fix window before going public, and after release credit the reporter in the advisory and state the affected versions and mitigations.
- The fix reaches the release notes through its Conventional Commit subject; the [release page](../release.md) owns how the changelog is produced.
