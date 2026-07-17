# Publishing to the Chrome Web Store: decision checklist

> This doc is a **decision checklist**, not a "we have decided to do this".
> Publishing would remove the biggest current adoption hurdle (manually loading
> an unpacked extension), but it is a **product commitment**: a developer
> account, a privacy policy, review risk, and one migration that affects the
> existing "pinned extension ID" design. Whether to publish is an RFC/ADR-level
> decision under GOVERNANCE (it touches distribution and the security
> boundary); open an issue/ADR to decide first, rather than going straight to
> a PR.

## The number one trap: publishing changes the pinned extension ID

The entire install flow depends on one **fixed** ID, `mkjjlmjbcljpcfkfadfmhblmmddkdihf`
(derived from the `key` in
[`src/apps/extension/manifest.json`](../src/apps/extension/manifest.json));
[`install.sh`](../install/install.sh) / [`install.ps1`](../install/install.ps1)
write it into the native host manifest's `allowed_origins`.

**But the Chrome Web Store assigns a store-controlled ID on first upload, and the store
ignores the `key` in the manifest.** The published extension will therefore **almost
certainly get a different ID**, and Chrome will **refuse the native messaging connection**
because `allowed_origins` does not match: the binary is installed, yet the extension
cannot connect.

**Mitigations that must be planned:**

- After the first upload, take the store-assigned ID and add it to `allowed_origins`,
  ideally **trusting both IDs at once**: the store ID (store users) plus the current
  pinned ID (unpacked / developers).
- Update [`install.sh`](../install/install.sh)'s `PINNED_EXTENSION_ID`,
  [`install.ps1`](../install/install.ps1), and
  [`scripts/check-extension-id.ts`](../scripts/check-extension-id.ts) in step so they
  trust both IDs.
- Optional: backfill the store listing's public key into the manifest `key` so unpacked
  loads also get the store ID. This changes today's pinned ID, so it needs weighing.

## What it solves, and what it does not

- Solves: **removes "wall 1"**. No more developer mode "Load unpacked"; one-click
  "Add to Chrome" that survives Chrome restarts, and far friendlier to managed/enterprise
  Chrome.
- Does not solve: **the installer stays**. The store only distributes the **extension**.
  Users still must run `install.sh` / `install.ps1` to install the **native host binary +
  manifest**. So this tears down one wall, not all of them.

## Prerequisites

- [ ] A Chrome Web Store **developer account** (one-time **$5**; you must register it
      yourself, I cannot create accounts).
- [ ] A **privacy policy URL** (**required** for this project: the extension reads page
      content, cookies, and web storage). It can live under `docs/`.
- [ ] Store listing assets: 1-5 screenshots (1280x800 or 640x400), a 128px icon
      (`src/apps/extension/icons/icon128.png` already exists), short + detailed descriptions, a
      category, and support/homepage URLs.

## Review risks specific to this extension

Google's review will focus on the following items; prepare written justifications in
advance:

- [ ] **`page_eval` (executes arbitrary JS)**: the highest rejection risk. Justification:
      a developer tool that requires user confirmation on every call; consider shipping
      the store build with this tool **disabled by default**.
- [ ] **`chrome.debugger`** (used by `page_snapshot_precise`): a sensitive permission that
      needs an explanation.
- [ ] **Broad host / optional permissions + native messaging**: explain the localhost-only,
      per-run-secret bridge and the per-site authorization model, and link the
      [threat model](./security/threat-model.md).
- [ ] **"Does it use remote code"**: answer truthfully. `page_eval` executes
      **user-supplied** JS, not remotely fetched code; word the form precisely.

## Packaging and submission

- [ ] Produce the store zip (the release pipeline already emits
      `chromium-bridge-extension-<tag>.zip`; confirm it is the uploadable `dist/`).
- [ ] Confirm the `manifest.json` version matches Cargo
      (`scripts/check-version.ts` already enforces this).
- [ ] Decide whether the `key` field stays (keep it to preserve a consistent unpacked ID,
      or hand it to the store; see the number one trap).
- [ ] Upload, fill in the data-use disclosure + privacy policy, and submit. Review takes
      **days to weeks**, and you **lose instant update control** (every update goes
      through review).

## After publishing

- [ ] Wire the store ID into `allowed_origins` + both installers (see the number one trap).
- [ ] Rewrite the README's "Load the extension" section to "Add from the Chrome Web
      Store", keeping unpacked as the developer/advanced path.
- [ ] Update `docs/`, and add an **ADR** recording the decision (per GOVERNANCE,
      distribution changes are major changes).
- [ ] Optional: automate publishing with a CI step (`chrome-webstore-upload` or similar),
      or keep it manual.

## Conclusion / recommendation

Publishing is the usability improvement with the **largest single payoff**, but it is a
product commitment: the $5 account, a privacy policy, the review risk around
`page_eval`/`chrome.debugger`, ongoing review latency, and the ID migration work above.
Because it touches distribution and the security posture, it is an **RFC/ADR-level**
decision under this project's [GOVERNANCE](../GOVERNANCE.md): open an issue and settle it
in discussion first, then act, rather than a quick PR.

## Related

- Security boundaries and threat model: [SECURITY.md](../SECURITY.md),
  [security/threat-model.md](./security/threat-model.md),
  [security/trust-boundaries.md](./security/trust-boundaries.md).
- Pinned ID and install artifacts: [architecture.md section 4.3](./architecture.md#43-install-artifacts).
- Release pipeline and the extension zip: [release.md](./release.md).
