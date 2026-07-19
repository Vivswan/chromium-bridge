# ADR-0031: Touch ID confirmations and presence-gated capability grants

- Status: Accepted
- Date: 2026-07-17
- Extends: [ADR-0021](0021-enrollment-ceremony.md) (the Secure Enclave
  enrollment key and its user-presence ACL, reused here as the presence
  primitive), [ADR-0024](0024-multi-client-attested-pairing-and-broker.md)
  (the trusted-client allowlist that pairing now gates on presence),
  [ADR-0027](0027-extension-rehaul-off-dom-confirmation-wxt-i18n.md) (the
  off-DOM confirmation surface and its provider seam),
  [ADR-0030](0030-global-kill-switch-and-audit.md) (the kill switch, whose
  release is the first presence-gated act, and the audit trail that records
  which rung authorized every grant)

## Context

Two capability-restoring acts needed a human, not just a same-user process:
releasing the kill switch, and pairing a trusted client. ADR-0030 built the
presence seam for the first and left the hardware behind it a stub; the
second wrote the allowlist on nothing more than reaching the CLI. The
presence symmetry rule the rebuild settled on is the frame: removing
capability is always friction-free (kill, revoke, uninstall are the
fail-closed direction), but restoring or granting it requires proof that a
human is at the machine.

Separately, the two crown-jewel tools - `page_eval` (arbitrary JS in the
page) and `page_upload` (a local file leaves the disk) - were confirmed only
by a button in an extension window. That window is out of a page's reach
(ADR-0027), which defeats a hostile web page, but it is not out of reach of
another program the user is running: anything that can drive the extension's
own pages could answer the prompt. For the highest-risk actions we wanted an
approval that no software on the machine can forge - one that requires a
finger on the sensor.

macOS gives two candidate primitives. We measured both:

- LocalAuthentication's `LAContext.evaluatePolicy(deviceOwnerAuthentication)`
  returned success **without any fresh user interaction** when the session was
  already authenticated. It is a check that the device has an owner, not a
  proof that the owner just acted, so it is unfit for a presence gate.
- A Secure Enclave signing operation on a key whose ACL carries
  `kSecAccessControlUserPresence` cannot complete without a live Touch ID (or
  login-password) response. This is the primitive ADR-0021 already relies on,
  and the one the hardware proof (`just touchid-proof`) confirmed
  prompts on real hardware.

## Decision

### 1. Presence is a Secure Enclave signing operation, never LocalAuthentication

`presence::require_presence(reason, floor)` is the single gate for every
capability-restoring act. It runs a ladder:

1. the hardware rung, on macOS, signs a throwaway challenge with the
   enrollment key. The signature is discarded; the security property is that
   the user-presence-gated Enclave operation *succeeded*, which it cannot do
   without a human. Success is `touch_id`.
2. the interactive floor, chosen by the calling surface, when hardware is
   genuinely unavailable (non-macOS, or no Enclave key on this machine).

The ladder never falls down on refusal. A hardware check that ran and was
refused - a cancelled prompt, a failed scan - returns an error and never
retries as the softer floor. An attacker who can make the prompt fail must
not thereby downgrade the gate. Only genuine unavailability reaches the floor,
and the floor is itself a human check.

The floors, one honest option per surface:

- `CliConfirm`: an explicit typed phrase on the CLI's own controlling
  terminal. A non-terminal stdin is refused **before** any hardware prompt is
  raised, so a background script cannot use the gate to flash an unexplained
  Touch ID sheet at the user (tap phishing).
- `ExtensionConfirm`: the extension options page's confirmation dialog,
  attested by the native-messaging channel that delivered the request
  (`allowed_origins` plus the SW sender gate).
- `AppConfirm`: the desktop app's own modal confirmation. The app must show it
  before calling the core, exactly as the extension floor's evidence lives in
  the channel rather than in this process.

Every grant is audited with the rung that authorized it (`auth=touch_id` /
`cli_confirm` / `extension_confirm` / `app_confirm`), so a hardware approval
is never conflated with a floor confirmation in the trail.

### 2. Kill-switch release and client pairing are presence-gated

`kill::release` already demanded a `PresenceAttestation` (ADR-0030); with the
hardware rung real, releasing the switch now takes a Touch ID tap on an
enrolled Mac. `allowlist::pair` now takes an attestation too, and the new
`allowlist::pair_client_with_presence(name, anchor, surface, floor)` is the
one entry point every surface uses to grant harness capability: it validates
the request before prompting (a malformed name can never raise a sheet), runs
the ladder, audits the outcome, and only then writes the allowlist. Revocation
stays ungated - removing capability is always friction-free.

### 3. page_eval and page_upload confirmations route through the Enclave

The confirmation provider seam (ADR-0027) gains a second provider. For the
`eval` and `upload` kinds, when the user setting is on and the device is
capable (macOS, a pinned host key, no compromise mark), the confirmation is
answered by a host Enclave signature over a fresh nonce whose context binds
the digest of exactly that confirmation's kind, origin, and detail. The
extension verifies the signature against its **pinned** key, over a presence
domain distinct from the enrollment domain, so neither statement type - "I am
the enrolled host" and "the user approved this one action" - can ever be
replayed as the other. The window still opens: it shows what is being
approved, but it renders display-only (no Allow button), and the service
refuses a window-side approval for such a payload. The tap is the only
approval. Denial stays reachable from the window, because refusing is the
friction-free direction. A presence proof that fails verification is not a
"no"; it is evidence the signer is not the pinned host, and it marks the
bridge compromised.

### 4. Per-action Touch ID is a user setting; enrollment Touch ID is not

`touchIdConfirm` (default on) governs only clause 3. Opting out sends the two
kinds back to the off-DOM window confirmation - still confirmed, just not
hardware-backed. The enrollment key and its user-presence ACL, which anchor
the host's identity and now the presence gate, are mandatory and not
opt-out-able.

## Consequences

- The two crown-jewel tools, and the two capability grants, now cost a
  physical tap on an enrolled Mac. That is friction by design, on exactly the
  actions where forgery hurts most.
- The hardware rung depends on enrollment. On a Mac with no Enclave key, and
  on every non-macOS platform, these acts use the interactive floor - a real
  human confirmation, just not hardware-attested. The threat model names this
  honestly rather than implying hardware everywhere.
- LocalAuthentication is not a dependency. The presence primitive is the
  Enclave key the codebase already vets and proves, so no new framework
  binding enters the security core.
- The gate cannot be fully verified without a finger on the sensor. The
  headless suites exercise every reachable path (the no-downgrade rule, the
  refused-window approval, forged and replayed proofs, the floors); the
  hardware path itself is driven by `just touchid-gates`, a runbook
  the user runs to see each prompt appear.

## Residual risk

The conceded same-user boundary is unchanged: a process running as the user
can still edit `revocation.json` or substitute the host binary, and the kill
switch and allowlist were never a defense against that (ADR-0025/0030). The
presence gate raises the bar on the specific act of *granting* capability
through our own surfaces - it makes a silent, script-driven grant impossible
where the hardware exists - and names the floor, and the same-user residual
beneath it, rather than implying they are closed.
