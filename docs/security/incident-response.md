# Incident response runbook

> A realistic security incident handling process for a single-maintainer
> project, consistent with the reporting channel in
> [SECURITY.md](../../SECURITY.md) and the assets/trust boundaries in
> [threat-model.md](threat-model.md). The trust boundaries are enumerated in
> [trust-boundaries.md](trust-boundaries.md); tool risk is in
> [tool-risk-matrix.md](tool-risk-matrix.md).

## What counts as a security incident

A compromise, or suspected compromise, of an asset protected in
[threat-model.md](threat-model.md). For example:

- a page operation executed on an **unauthorized origin**, bypassing the site allowlist
  or the confirmation prompt;
- cookies / storage / page content / eval return values leaked past masking;
- the bridge socket accepted an **unauthenticated** local peer, or the host manifest's
  `allowed_origins` was modified;
- `page_eval` or its confirmation channel abused with irreversible consequences.

Not incidents: anything requiring the machine to be compromised first, or a malicious MCP
client the user configured themselves (trusted by design, see
[SECURITY.md's Scope](../../SECURITY.md#scope)).

## Reporting channel

**Do not open a public issue for a security problem.** Use GitHub's
**[Report a vulnerability](https://github.com/Vivswan/chromium-bridge/security/advisories/new)**
(Security -> Advisories) for a private report, including: what the attacker can do (the
impact) and which trust boundary is crossed, reproduction steps or a PoC, and the affected
versions/commits. As a small project, we will acknowledge within days and ask for a
reasonable fix window.

## Triage

After receiving a report, grade it with these questions (they track the blast radius in
[tool-risk-matrix.md](tool-risk-matrix.md)):

1. **Which trust boundary is crossed?** (See boundaries 1 through 4 in
   [trust-boundaries.md](trust-boundaries.md); boundary 4, the page boundary, is the most
   critical.)
2. **What can be read or changed?** Does it reach credentials (cookie/storage tokens)?
   Are there write or irreversible consequences?
3. **How strong are the preconditions?** Does it require the user to have authorized an
   origin, installed the extension, or a local same-UID process?
4. **Is it reproducible?** Is there a PoC?

Use that to decide between "mitigate now" and "schedule a fix". Credential leakage and
allowlist/confirmation bypasses are the highest priority.

## Immediate mitigation (user side, no code change needed)

Users can take these actions themselves to **shrink the blast radius** before a patch is
ready:

- **Disable a single tool**: on the extension Options page, add the affected tool to
  `disabledTools` (maps to `TOOL_DISABLED`, see
  [`ERROR_SPECS` in error.rs](../../src/packages/core/src/error.rs)); a high-risk tool such as `page_eval`
  should be disabled first.
- **Revoke the allowlist / turn off all-sites**: in Options / the popup, remove the
  authorization for the affected origins, and confirm `allowAllSites` is off (see
  [ADR-0004](../adr/0004-allowlist-with-optional-host-permissions.md),
  [ADR-0011](../adr/0011-options-page-for-settings.md)). Removing an authorization also
  revokes that origin's host permission.
- **Kill switch**: disable or remove the Chromium Bridge extension at
  `chrome://extensions`. Once the extension stops, the native host gets EOF on stdin and
  exits, which severs the bridge. If needed, also end the MCP client session so the MCP
  server process exits (confirm not reachable with `doctor`, see
  [operations.md](../operations.md)).
- **Uninstall the host manifest**: after deleting the native messaging host manifest,
  Chrome can no longer spawn the host (paths in
  [architecture.md section 4.3](../architecture.md#43-on-disk-artifacts)).

> Mitigation order, from light to heavy: disable the high-risk tools first, then revoke
> the allowlist, then disable the extension, then uninstall the manifest.

## Fix and verification

- Locate the **invariant** that was crossed (see
  ["invariants that must not regress" in trust-boundaries.md](trust-boundaries.md#invariants-that-must-not-regress)).
- The fix goes through the **security-relevant change** gate: fill in the
  [security-change checklist](../../.github/ISSUE_TEMPLATE/security-change.yml), update
  [tool-risk-matrix.md](tool-risk-matrix.md), and if a trust boundary changed, update
  [threat-model.md](threat-model.md) too.
- **A negative security test is mandatory** to prove the boundary holds again (adding
  positive cases alone is not enough), per
  [SECURITY.md's review bar](../../SECURITY.md#security-relevant-changes-review-bar).

## Release and disclosure

- Tag and release the fix per [release.md](../release.md); pre-1.0 only the latest
  release is supported (see
  [SECURITY.md's Supported versions](../../SECURITY.md#supported-versions)), and security
  fixes ship as a new patch/minor.
- Coordinate disclosure through a GitHub Security Advisory: give the reporter a
  reasonable fix window before going public, and after release, credit the reporter in
  the advisory and state the affected versions and mitigations.
- Record the fix in [CHANGELOG.md](../../CHANGELOG.md).

## Related

- Reporting channel and review bar: [SECURITY.md](../../SECURITY.md).
- Assets, actors, non-goals: [threat-model.md](threat-model.md).
- Boundaries and invariants: [trust-boundaries.md](trust-boundaries.md).
- Running and diagnostics: [operations.md](../operations.md).
