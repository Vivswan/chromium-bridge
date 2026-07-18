# ADR-0032: Host-owned policy settings and paired language sync

- Status: Accepted
- Date: 2026-07-18
- Extends: [ADR-0021](0021-enrollment-ceremony.md) (the Secure Enclave
  enrollment key and its pinned public key, reused here to sign policy),
  [ADR-0028](0028-contracts-dissolved-into-rust-core.md) (the Rust core as
  the single contract source; the policy schema moves under it),
  [ADR-0029](0029-desktop-app-management-surface.md) (the desktop app, which
  becomes a policy-editing surface, alongside the signed CLI), [ADR-0031](0031-touch-id-confirmations-and-presence-grants.md)
  (presence-gated capability grants; policy writes that grant capability join
  that pattern)
- Amends: [ADR-0011](0011-options-page-for-settings.md) (the options page
  stops owning security policy; it keeps the browser-owned settings),
  [ADR-0030](0030-global-kill-switch-and-audit.md) (the extension's
  `kill_release` path is retired, release becomes app/CLI only; and
  decision 4's healthy-host-pushes-nothing connect asymmetry is reversed:
  a policy-capable host pushes policy and language state at every connect)

## Context

Every configurable setting lives today in one Zod schema
(`src/packages/shared/src/settings.ts`), persisted in the extension's
`chrome.storage.local`, edited on the extension options page. That bag mixes
two very different kinds of state. Some of it is genuinely browser-local:
which origins the bridge may touch, whether tabs get grouped, the pairing
approval the user gives in the extension UI. The rest is security policy:
whether `page_eval` and `page_upload` exist at all, which confirmations can
be skipped, how long a same-origin grace window lasts, which tools are
disabled. The desktop app (ADR-0029) is where the user manages the bridge,
and the control-tower design exploration puts the policy controls there,
behind Touch ID. Two decisions are settled and this record specifies them:

1. Policy moves host-side. The capability grants (`cdpMode`,
   `fileUploadEnabled`, `handleDialogEnabled`, `pageEvalEnabled`), the
   confirmation policy (`confirmHighRiskClick`, `confirmPageEval`,
   `touchIdConfirm`, `confirmTabClose`, `warnPreciseSnapshot`, `evalMask`,
   `hostReverifyMs`, `confirmGraceMs`), the per-tool
   disable list, and the confirmation timeouts (`clickToastTimeoutMs`,
   `evalToastTimeoutMs`) are owned by the host, persisted host-side, and
   pushed to the extension over native messaging. The extension enforces the
   received policy at its trust boundary and treats a missing or unverifiable
   policy fail-closed. Kill release moves with them: it becomes an app/CLI
   act behind the ADR-0031 presence gate. The extension keeps what is
   browser-owned: the origin allowlist, `allowAllSites`, `groupTabs`, the
   pairing approve-half, and kill ENGAGE.
2. `uiLanguage` becomes a shared preference while paired: a change on either
   side propagates through the host; an unpaired extension keeps its local
   value.

Moving policy to the host is not a neutral relocation, and the threat model
has to be stated before the mechanism, because the naive design makes the
bridge weaker, not stronger. ADR-0021 concedes that after enrollment a
same-user process can substitute the native-messaging manifest or the host
binary and become the peer on the port; ADR-0025 builds on that concession
(the forged `enclave_revoked` residual). What bounds that substituted host
today is exactly the state this record moves: the confirmations and
capability gates live in the extension's TRUSTED_CONTEXTS storage (#32,
ADR-0027), which no host, genuine or substituted, can write. A substituted
host can send ops, but every high-risk op still confirms on the extension's
own surface, `page_upload` stays off unless the user enabled it, and the
crown jewels route through the Touch ID provider. If "the host pushes
policy" meant "the extension applies whatever the port says", a substituted
host could push `confirmHighRiskClick: false, pageEvalEnabled: true,
confirmPageEval: false, touchIdConfirm: false` and convert the conceded
drive-with-confirmations residual into silent full control. That would be a
grant of capability riding on channel presence, which is precisely what the
zero-trust rules forbid.

So the mechanism below is built around one asymmetry: policy that grants
capability must carry proof no same-user process can forge, and policy that
only removes capability may travel free, because failing closed is the
direction every forgery is allowed to point (the same symmetry rule as
ADR-0031's grants and ADR-0025's revocations).

### Resolved questions (decided 2026-07-18)

The first amendment left four points open pending the user's decision, and
review of it raised a fifth: whether the touched-field set that scopes the
restriction-overlay retention should travel beside the signed document or
inside it. All five are decided; the decisions below are written with the
answers folded in, and this list records each answer with the decisions it
touches:

- The first-run import screen ends in a Touch ID tap on both paths.
  "Restore these" and "start fresh" each sign revision 1, so a baseline
  exists only because a present user produced one. Decision 8 stands as
  drafted. Touches: decision 8.
- `requireEnrollment` is retired as a policy field. Enrollment is the
  spine of the rebuilt model - the pin, the signatures, and the presence
  gates all hang off it - so an off switch is a footgun, not a setting.
  The migration drops the field (decision 8); enrollment is simply
  required. Touches: Context's field inventory, decisions 1, 2, 4, 8.
- The CLI gets policy read AND write, equal to the app. A grant's Touch ID
  cost comes from the enclave key's user-presence ACL, which prompts
  identically from any signed binary, so an app-only write rule bought no
  security. The fail-closed edge: where no enclave key exists, the CLI
  grant path is refused outright. Touches: decisions 1, 5, 8.
- The toast timeouts' declared direction is confirmed conservative as
  drafted: `clickToastTimeoutMs` and `evalToastTimeoutMs` are permissive
  as they grow, so raising one needs a tap. Decision 2's table stands.
  Touches: decision 2.
- The touched-field set moves inside the signed document bytes, so the
  tap covers which fields a write supersedes and a fresh signature is
  never a blanket relaxation warrant. Touches: decisions 3, 4, phases 1
  and 3.

## Decision

### 1. The split: host-owned policy, browser-owned state

Host-owned (the policy document, decision 2): the four capability grants,
the eight confirmation-policy fields, `disabledTools`, and the two
confirmation timeouts listed above. These are decisions about what the
bridge may do and what it must ask before doing; they belong to the machine,
not to one browser profile, and their editing surfaces are the desktop app
and the signed CLI (decision 5).

Browser-owned (stays in `src/packages/shared/src/settings.ts` and
chrome.storage): the per-origin allowlist and `allowAllSites` (both are
projections of Chrome's own optional-host-permissions state, granted through
a browser gesture the host cannot make), `groupTabs` (pure browser UX), the
pairing approve-half (the extension's half of the ADR-0021 ceremony, which
is only meaningful as an in-browser act), and kill ENGAGE (the brake must
stay one action away on every surface; ADR-0030's asymmetry is unchanged).

`uiLanguage` is neither: it is a shared preference with its own lane
(decision 7), deliberately outside the signed policy document so that
changing the display language never raises a Touch ID sheet.

### 2. The policy document is Rust-canonical

The policy schema, its defaults, and its wire shape move into the core as a
`PolicyDoc` (`src/packages/core/src/policy.rs`), following ADR-0028: the
enforcement core is the single source, and the TS side is generated. `just
gen` emits `src/packages/shared/src/policy.gen.ts` with the Zod validator
(strict objects, the same salvage posture as today's settings), the
defaults, and the per-field direction metadata below. CI's stale-diff gate
covers it like every other generated artifact. `settings.ts` shrinks to the
browser-owned fields and loses the policy ones in the cleanup phase.

Every policy field carries a declared permissive pole, in the catalogue
itself: the value direction that grants capability. `pageEvalEnabled`,
`fileUploadEnabled`, `handleDialogEnabled`, `cdpMode` are permissive at
`true`; every `confirm*`/`warn*`/`evalMask` flag is
permissive at `false`, and so is `touchIdConfirm`, which neither glob
matches and is therefore declared here explicitly; `confirmGraceMs`
matches `confirm*` lexically but is no flag, so it is deliberately
excluded from that glob and classified with the grow-direction fields: it
and the two toast timeouts are permissive as they grow; `disabledTools`
is permissive as the set shrinks.
`hostReverifyMs` gets a declared custom order, because its numeric order
lies about its security order: 0 means never re-verify and is the MOST
permissive value, and among positive values a longer interval means fewer
checks, so permissiveness grows with the number everywhere except at 0,
which tops the scale. The direction table expresses that order explicitly
(conceptually, 0 maps to infinity before comparing). A cargo test refuses a
field without a direction, so nobody can add a setting that the comparison
below silently ignores, and a second test pins the `hostReverifyMs` order
specifically, since it is the one a naive comparator gets backwards. The
direction table is emitted into `policy.gen.ts` and the extension
recomputes every comparison from it itself; it never trusts a host's claim
about which way a change points.

The wire envelope does not change. `BridgeReq`/`BridgeResp` are untouched (a
new envelope field is a breaking protocol change by construction, per the
`deny_unknown_fields` posture documented on `BridgeReq`), so the
double-derivation gate (`just check-envelope`) needs no new erasure rules;
what it needs is nothing, and a cargo test pins that the new frame types are
host-control tags (`host_control_type`), never envelope traffic. Policy
rides host-handled control frames exactly like ADR-0025/0030's admin frames:
new `EnclaveControl`/`AdminControl`-style variants, classified in
`classify_nm_frame`, answered by the host, dropped when the server leg tries
to inject them. The extension-side frame parsers are hand-written
looseObject validators in `src/packages/shared` next to the existing
enclave/admin ones; the `PolicyDoc` payload inside them is validated by the
generated strict schema, so the document itself has one derived parser and
no hand-written twin to drift.

### 3. Grants are presence-signed; restrictions travel free

The host persists at most one signed policy baseline: the serialized
document bytes, a signature, and the signing key id (recorded for the
host's own bookkeeping; the extension never trusts it, below). The
signature is a Secure Enclave ECDSA P-256/SHA-256 signature by the ADR-0021
enrollment key over `UTF8("chromium-bridge-policy-v1") || 0x00 ||
doc_bytes`: a third domain, NUL-separated and injective like the other two,
so a policy signature can never be replayed as an enrollment or per-action
presence proof, nor either of those as a policy. There is no
canonicalization step anywhere: the host signs and stores the exact bytes,
the extension verifies the exact bytes it received against its pinned key
and then strict-parses those same bytes. Two scoping fields live inside
the signed bytes, so the tap covers them along with the values: a monotonic
`revision`, a u64 constrained to the JS-safe integer range (the same
posture as `BridgeReq::id`), so both parsers read the same number, and
the `touched` set of the write that produced the document - the fields
that write explicitly edited, whose role in overlay retention and the
ratchet is below.

Because the enrollment key's ACL requires user presence, producing this
signature costs a Touch ID tap, and that is the point: the tap the locked
decision requires for capability grants IS the signature. A policy write
that moves any field toward its permissive pole relative to the current
EFFECTIVE policy (the signed baseline with its restriction overlay
applied, decision below; anchoring on the baseline alone would let
"undo a restriction" masquerade as a non-grant, which the extension's
ratchet would then rightly refuse) goes through
`policy::set_signed(doc, touched, surface, floor)`, which embeds the
touched set in the document, validates
the result before any prompt can appear (a malformed document never
raises a sheet, the ADR-0031 tap-phishing rule), then signs. The Enclave
signing operation over the policy message is itself the presence act,
exactly as ADR-0031 clause 3 makes the signature over a confirmation
digest the approval; there is no separate throwaway-challenge round and
so no second prompt. The
presence module grows a sign-as-presence primitive for this (sign the
caller's message on the hardware rung, report which rung authorized), so
`set_signed` never takes a pre-made attestation and can never double
prompt; `policy::restrict` takes no attestation at all. On success
`set_signed` bumps `revision`, writes atomically under the runtime lock,
and audits the outcome with the rung that authorized it. An existing
unsigned restriction overlay is retained across the write and re-applied
on top of the new baseline, minus its entries on the fields the write
explicitly touches. The touched set is named by the editing surface, not
reconstructed from a document diff (an undo
of an overlay restriction can leave the baseline value unchanged, so no
diff can see it), and it travels inside the signed bytes (resolved
questions above), so the supersession is itself signed: the extension
reads which fields the tap covered from the verified document, never
from a frame field a substituted host could edit. The tapped edit
supersedes the overlay entry on the
field it touches, which is how an undo of a restriction (a relaxation
like any other, above) actually lands, while entries on untouched fields
survive as overlay, never silently folded into the signed baseline (the
new document carries baseline values, not effective ones, on fields it
does not touch). Folding the overlay into the baseline stays the
separate, explicit act the reinstall paragraph below offers, and it is a
signed write like any other, defined here so it does not fall between
the lanes: a new revision whose document carries the folded fields'
effective values and whose touched set names them, emptying their
overlay entries. It leaves the effective policy exactly in place, so the
tap it costs is not the grant tap of this lane's rule - it is the plain
fact that nothing alters the signed baseline without a fresh signature.
The
ladder's no-downgrade rule applies unchanged:
a refused or failed hardware prompt is a refusal, never a fallthrough to
a floor. Where hardware is genuinely
unavailable, the write is gated by the surface's interactive floor and
stored unsigned - the app's floor; the CLI's grant path is signature-only
and refuses instead (decision 5) - and what an unsigned baseline is worth
at the enforcement
boundary is defined by the unpinned lane below, not by the floor.

A write that moves every field toward its restrictive pole relative to the
same anchor, the current effective policy, or leaves it in place, needs no
tap (so an "undo" of an earlier restriction never rides this lane, even
though it stays under the baseline: it relaxes the effective policy, and
relaxations are the other lane). It is stored and pushed unsigned as the
current restriction overlay. The extension accepts it only after
independently checking, field by field against the direction table, that it
restricts the baseline it has verified, and the ratchet (below) separately
refuses it if it would relax the effective policy. A forged restriction is
therefore possible and harmless: it is a denial of service against the
user's own bridge, the same class as the forged `enclave_revoked` ADR-0025
names, and it points fail-closed.

What a forged push can never do is relax, because the extension keeps a
ratchet. In its #32 trusted storage it persists the effective policy it last
applied, alongside the baseline's `revision`. An incoming policy may set a
field to a more permissive value than the stored effective policy only when
it arrives as a verified signed baseline with a strictly higher revision
than the stored one AND that baseline names the field in its signed
`touched` set: a signature warrants relaxation on exactly the fields the
user edited under it, never on the document at large. Replaying the
current baseline unchanged is
idempotent; replaying an older signed baseline fails the revision check;
replaying the baseline after the user applied an unsigned restriction fails
the ratchet check, because relaxation without a fresh signature is refused
no matter what signature the stale bytes carry; and pushing a genuine
fresh baseline with its retained overlay stripped off fails the
touched-set check on every stripped field the tap did not name. The
anchor for all of this
is the same storage that anchors the enrollment pin, which is exactly the
trust class the old extension-owned settings had. Verification and the
ratchet are keyed on the extension's own pin and nothing else: the frames
carry no key identity the extension honors, a signature either verifies
against the pinned key or the policy is refused, and the ratchet's scope is
the pinned key id read from the extension's own pin storage. (A frame-
supplied key id would hand a substituted host a ratchet-reset lever; the
pin-only rule is the same one `enclave-verify` already enforces for
presence proofs.) A `pair --reset` mints a new key and a new pin through
the user-present ceremony, and the first baseline verified under the new
pin starts a fresh ratchet scope.

Two honest limits. On a machine where the extension has no pin (non-macOS,
or an unenrolled Mac), nothing can sign and nothing can verify, so the
signature lane does not exist: `policy_current` arrives with baseline bytes
and no signature, and strict parsing is the entry point (there is no
verify-first step because there is nothing to verify; the Zod validators
are exactly the parsers for untrusted input). The comparison anchor is the
stored effective policy, as everywhere: a parsed document that only
restricts it applies silently, and one that would relax it is held
unapplied, shown in the extension's off-DOM confirmation window (ADR-0027;
a surface no web page and no host process can read or answer), and applied
only on the user's explicit approval, after which it ratchets as usual.
Before any policy has ever applied there is no stored effective, so the
first document is by definition a relaxation candidate and always goes
through the window; on unpinned machines the cutover therefore always rides
a user gesture. A forged push on an unpinned machine costs the attacker a
visible, unexpected prompt rather than a silent grant, and a denial changes
nothing. The window is out of a web page's reach, not out of every
program's: ADR-0031's concession that software driving the extension's
own pages could answer its prompts applies to this lane unchanged, which
is part of why the pinned lane never falls back to it. The no-downgrade
rule binds the lanes: an extension that has a pin never accepts an
unsigned relaxation, from any frame, on any platform, for any reason; the
window lane applies only where no pin exists. And a reinstalled extension
has an empty ratchet (and, until re-pairing, no pin), so after re-pairing
it will accept the current signed baseline as-is, including grants the
user had turned off
through unsigned restrictions since that baseline was signed; folding
long-lived restrictions into a fresh signed baseline (one tap in the app)
is the way to make them survive a reinstall, and the app offers it.

Key disposal is part of the story, because a baseline outlives its key
only as a trap. `chromium-bridge revoke` and `pair --reset` (ADR-0025)
also clear the signed baseline in the same critical section that deletes
the key: the signature is an artifact of the dead key, and a genuine host
that kept pushing it to a freshly re-pinned extension would be
manufacturing the very pin-mismatch that means "compromised". The document
content survives as an unsigned draft the app offers to re-sign with one
tap after re-pairing. On the extension side, pinning a new key resets the
policy state with the rest of the pairing state: no stored effective, the
deny baseline (decision 4), until the first baseline verified under the
new pin. Re-pairing is itself the user-present ceremony, so this reset
cannot be reached silently.

### 4. Delivery, and fail-closed on absence

The policy travels host-to-extension in `policy_current { ok, baseline?,
sig?, overlay?, error? }`: `baseline` is the exact signed document bytes
(base64, so the signed artifact survives the JSON hop byte-for-byte),
`sig` its signature, and `overlay` the current restriction overlay as a
plain JSON document. The extension verifies the signature over the decoded
baseline bytes first and strict-parses those same bytes only after the
signature holds; the overlay is strict-parsed and then direction-checked
against the verified baseline. The host pushes `policy_current` unsolicited
at every port connect and on every observed policy change (riding the same
watch tick as the revocation and kill pushes, ADR-0025/0030). A
`policy_get {}` request frame exists for on-demand refresh, but the
extension sends it, like every new frame in this record, only to a host
that has already identified itself by pushing a policy frame on the current
connection. That ordering rule is load-bearing for compatibility, not
politeness: an old host classifies an unknown frame type as `Forward`, the
MCP server parses everything on the browser leg as a strict `BridgeResp`,
and the parse failure tears down the browser connection (`session.rs`). So
the extension never speaks first, and against an old host the new frames
simply never flow. Both frame types join `host_control_type`, so a
misbehaving or substituted MCP server cannot inject a `policy_current`
down the server leg.

The extension consumes policy only at its own gate, and its stored state
only ever improves for the attacker's victim, never for the attacker. On
every applied verified policy it updates the ratcheted effective copy in
trusted storage; across service-worker restarts it enforces that stored
copy (verified and ratcheted when written; the #32 cold-start window
applies to it and is already named in the threat model). A push that fails
verification, in any way (bad signature, lower revision, malformed
document, an overlay that does not restrict, a relaxation without a fresh
signature, a relaxation on a field outside the fresh signature's touched
set), changes nothing: the extension keeps enforcing the stored
effective policy, which is never more permissive than what the user last
saw applied, and surfaces the failure rather than smoothing it over. On a
pinned extension a signature that does not verify against the pin is
evidence about the signer, exactly as ADR-0031 treats a bad presence
proof. Falling back to defaults on a bad push is deliberately NOT the
behavior: defaults can be more permissive than a user's restricted
effective policy (an emptied `disabledTools`, re-enabled clicks), so
"garbage in, defaults out" would hand an attacker a relaxation lever made
of garbage.

Policy application is also ordered against decisions in flight: a
confirmation or other decision already in progress completes under the
policy it started with, and an accepted policy applies from the next
decision on. A policy arriving mid-confirmation therefore cannot relax,
or otherwise alter, an in-flight decision.

When there is no stored effective policy at all, the fail-closed baseline
applies: the generated defaults with every capability grant at its deny
value, `pageEvalEnabled` included, and every confirmation on. It is what
the extension enforces, not a stored effective the ratchet anchors on:
until a first policy verifies and applies there is no ratchet state,
which is why a reinstalled extension accepts the current signed baseline
as-is (decision 3). Where that
state can occur is bounded by the
cutover (decision 8): before an extension has ever applied a policy it
enforces its legacy local settings (today's exact system, which a host
cannot write), so the baseline governs only the genuinely policy-less
states, a fresh post-cutover install or a wiped profile, in which the next
accepted push replaces it within one connect.

Staleness is handled by a barrier, not a clock. A cached verified policy
does not expire: it is the user's standing choice, protected by the
ratchet. The exposed direction is the other one, the user tightening
policy in the app while the service worker slept, where the cached copy is
more permissive than the host's current store. The port is duplex, so
"the pull happens on connect" would not by itself stop one bridge op from
racing ahead of the policy push. Post-cutover, the extension therefore
gates op dispatch per host generation, and the gate opens only on
acceptance: until a policy push for the current connection has verified
and applied (through whichever lane the machine has), bridge ops are
refused, the same way the enrollment gate already blocks every request
until the storage restriction lands (ADR-0027). A push that fails
verification leaves the barrier closed; if garbage opened the gate, a
substituted host would send garbage precisely to run ops under the cached
copy. A host that never pushes, or only pushes junk, makes the bridge
refuse, which is the correct reading of a policy-capable peer gone silent
or gone wrong. The honest bound on what the barrier buys: a substituted
host holding the genuine `policy.json` can replay the genuine current
state, so the barrier guarantees the extension runs on the newest policy
it has ever accepted, not on the host store's ground truth. A tightening
the extension never received can be withheld by a substituted host until
the next genuine push - staleness that in truth lasts as long as the
substitution does, since a peer that stays substituted defers that push
indefinitely - but what the staleness can relax is bounded hard. With
the touched set
inside the signed bytes, replayed genuine artifacts can make the
extension laxer only on the fields the user actually touched-and-signed
in the newest baseline - which is the relaxation the tap approved -
because stripping the unsigned overlay off a fresh signature now fails
the touched-set check instead of riding the new revision, the hole a
touched set outside the signature would have left open. Where no pin
exists the bound is the extension-window approval, with the residual
that lane concedes above. Either way, nothing the extension ever applied
gets laxer without that signature or approval, field by field.

The host enforces its own policy too: dispatch in `mcp_server` refuses a
tool whose grant is off or that is in `disabledTools` with the existing
`TOOL_DISABLED` taxonomy code, before any bridge traffic. That is defense in
depth for the honest-host path, not a substitute for the extension's gate;
the extension keeps enforcing at its boundary precisely because the host may
not be ours.

### 5. The host-side store

Policy persists as `runtime_dir()/policy.json`: 0600 in the 0700 runtime
directory, versioned, `deny_unknown_fields`, written atomically under the
runtime lock, holding the signed baseline bytes, signature, key id, and the
current restriction overlay. The file is storage, not authority. A
same-user process that edits a signed baseline's bytes breaks the
signature; on an unenrolled Mac the baseline is stored unsigned and there
is no signature to break, but an edit there buys no more than the
unpinned lane already concedes (decision 3): the extension strict-parses,
applies silently only what restricts, and holds any relaxation for the
window approval. One
that edits the overlay runs into the extension's own direction check and
ratchet, which bound a forged overlay to restriction. Either way the
extension keeps enforcing its stored effective policy (decision 4), so
tampering here fails closed, never open, and adds no capability to an
attacker who could already delete the trust files (the ADR-0025 posture).
The genuine host reads the file fail-closed on both of its paths: an
unreadable or malformed store means "answer `policy_current` with
`ok: false`", never a silent default that could mask a tamper, and the
host-side dispatch check (decision 4) treats the same unreadable store as
deny-all.

All writes go through the core (`policy::set_signed`, `policy::restrict`),
and both editing surfaces call the same seams: the desktop app in-process,
the same pattern as `kill::release` and
`allowlist::pair_client_with_presence`, and the CLI (`chromium-bridge
policy` reads and edits; `doctor` reports the policy state and signature
validity). The CLI is a write surface as deliberately as the app is
(resolved questions above), because app-only writes never bought
anything: a grant's Touch ID cost comes from the enclave key's
user-presence ACL, which prompts identically no matter which signed
binary asks for the signature, so restricting grants to the app would
have been a rule about which window the sheet appears over, not a
security boundary. What keeps the second surface fail-closed is that the
CLI's grant path exists only as that signature. Where no enclave key
exists - non-macOS, an unenrolled Mac - `set_signed` from the CLI is
refused outright. That refusal is a deliberate policy-write exception to
ADR-0031's ladder, which would otherwise offer `CliConfirm` as the CLI's
honest floor: a floor-gated CLI grant would quietly create a
baseline-writing path on every platform the CLI ships to, which is
exactly the non-macOS hole decision 8 refuses, so for policy writes the
floor lane belongs to the app alone. The app's interactive floor on an
unenrolled Mac
(decision 3) therefore stays the single unsigned-grant surface, and
decision 8's non-macOS posture - no baseline can ever be written - now
rests on this platform gate rather than on a read-only CLI.
`policy::restrict` is free from either surface, as everywhere; without a
baseline there is nothing to restrict, so it adds no non-macOS write
path either.

Every policy transition is audited (ADR-0030): the fields that changed
direction, the surface, and for grants the presence rung that authorized the
signature, so a hardware-signed grant is never conflated with a floor grant
in the trail.

### 6. Kill release leaves the extension

ADR-0030 accepted the options page as a release surface because it was the
only user surface besides the CLI. The desktop app changes that, and release
is the single act in the bridge that restores capability wholesale, so it
moves to the strongest gates available: `chromium-bridge unkill` and the
app, both through `kill::release` and the ADR-0031 presence ladder (Touch ID
where hardware exists, one honest floor where it does not). The host now
refuses an extension-originated `kill_release` frame, audited, and the
extension UI drops the release control while keeping engage. Engage in
fact gains a surface, decided alongside this record and implemented
separately from it: the off-DOM confirmation window (ADR-0027) carries a
compact engage-only kill control, so the moment ADR-0030 built the brake
for - a confirmation the user does not recognize, already on screen -
honors the one-action rule without leaving the window. The
control-plane mode ADR-0030 built stays: a killed host still answers control
frames, so status, engage, and the policy pull keep working while killed.

### 7. Language sync

`uiLanguage` becomes host-canonical while paired, and it is deliberately not
policy: not signed, not ratcheted, not able to affect any security decision.
The host persists `{ value, seq }` (a u64 bumped on every accepted change,
constrained to the JS-safe range like the policy revision).
Three host-handled frames carry it: `lang_get {}`, `lang_set { value }`, and
`lang_current { value, seq }`, the last one pushed to the extension on every
change and returned as the reply to the other two; the desktop app reads and
writes the same state in-process and receives changes through the core's
watch, so a change on either side reaches the other through the host.

Loop prevention is the boring kind: an echo is suppressed by sequence, not
by guessing. Only a user gesture emits `lang_set`; applying a received
`lang_current` never does. A receiver applies a push if and only if its
`seq` is greater than the last sequence it applied, and records it; a
`lang_set` that does not change the host's value does not bump `seq`, so a
set-apply-set cycle has nothing to ride on. Values outside the generated
enum are refused and the previous value stands. The never-speak-first rule
of decision 4 covers these frames too: the extension sends `lang_set` and
`lang_get` only on a connection where the host has already pushed
`lang_current` (the host pushes it at connect alongside the policy), so an
old host never sees a frame it would fatally forward. An unpaired
extension, or one facing an old host, keeps its local value and its local
picker, unchanged from ADR-0027, including the rule that the picker renders
each language in itself.

A substituted host can forge `lang_current` and flip the UI language. That
is a nuisance with zero capability attached, which is why language gets the
free lane and policy does not.

### 8. Migration

The cutover is keyed on the first applied policy (verified under a pin,
window-approved without one), which keeps every version-skew combination at
today's behavior or stricter:

- A new extension enforces its legacy local settings until the first
  policy applies. Before cutover it snapshots the legacy
  bag into trusted storage (the import source, below); at cutover host
  policy wins, the dispatch barrier of decision 4 arms, and there is no way
  back to local policy (the ratchet takes over). The legacy fields
  themselves are deleted from chrome.storage only in the cleanup phase,
  after the import path has shipped. Until cutover, behavior is today's.
- A new extension against an old host never receives a policy push, so per
  the never-speak-first rule it never sends a policy frame either, and it
  stays on legacy behavior indefinitely. Harmless: that pairing is exactly
  today's system. The options page may advise "update the desktop app" when
  paired without ever seeing a policy push, as UI advice only, never
  enforcement.
- An old extension against a new host drops the unfamiliar `policy_current`
  push on the floor and keeps enforcing its local settings. That drop is
  an assumption about shipped code, so it is pinned as a test rather than
  trusted: phases 1 and 3 each carry an explicit requirement that an
  unrecognized push frame is ignored without tearing down the port. The
  host-side dispatch check (decision 4) still applies host policy on the
  honest path, so the combined enforcement is never more permissive than
  the old extension alone (the host policy itself may be laxer than the
  old extension's local settings, but the old extension keeps enforcing
  those).

Two platform postures ship in this record without a hardware grant
surface, named here rather than implied. An unenrolled Mac has the app
but no Enclave key: grants go through the app's interactive floor
(decision 3; the CLI refuses there, decision 5), the baseline is stored
and pushed unsigned, and the
extension's window lane is the approval surface. The first-run import
flow below reads on an enrolled Mac; on an unenrolled one the same
screen ends in the app's floor confirmation instead of a tap and stores
revision 1 unsigned, per decision 3. Non-macOS ships no grant
surface at all: the desktop app does not ship there, and the CLI's grant
path refuses wherever no enclave key exists (decision 5) - there is
nothing to sign with - so no baseline can ever be written and
a non-macOS extension stays pre-cutover on its legacy settings
indefinitely, the same posture as facing an old host.

Because grants require presence, the existing settings cannot be silently
grandfathered: importing `fileUploadEnabled: true` from chrome.storage into
a signed baseline without a tap would be a grant on channel evidence.
Instead, once a policy-capable host has identified itself and has no policy
store, the extension sends the snapshotted legacy bag once
(`legacy_settings { bag }`, host-handled, recorded as a pending import,
never applied). The app's first-run policy screen shows the imported values
against the defaults and ends in one Touch ID tap either way: "restore
these" signs revision 1 with the confirmed import, "start fresh" signs
revision 1 with the defaults. A user who abandons the flow entirely leaves
no baseline, and the extension stays pre-cutover on its legacy settings
until one lands, the same posture as facing an old host. Restriction
fields in the import (a populated `disabledTools`, confirmations already
on) are folded into the overlay
immediately, since they only remove capability. A legacy
`requireEnrollment` is dropped on import whatever its value: the field is
retired (resolved questions above), so an existing `requireEnrollment:
false` survives as history in the snapshot, never as policy - enrollment
is simply required. `uiLanguage` is imported
directly at first pairing: if the host value was never explicitly set, it
adopts the extension's; afterwards the host is canonical.

No `BRIDGE_PROTOCOL_VERSION` bump: every frame is additive and host-handled,
the envelope is untouched, and both old-peer combinations degrade to current
behavior. The deferred version/capability handshake (compatibility.md) stays
deferred; when it lands, the advertised capability set should be computed
from the effective policy, which this record makes possible but does not
wire.

## Why these choices

- Why sign with the enrollment key and not a new one. A signing key without
  a presence ACL can be exercised by any same-user process, so it
  authenticates nothing beyond the channel (the ADR-0021 lesson); a second
  presence-gated key would double the ceremony surface without adding a
  property. The enrollment key already has the pin distribution, the
  revocation story (ADR-0025), and the domain-separation pattern. One new
  domain string is the whole cost.
- Why sign bytes instead of a canonical form. JSON canonicalization is a
  parser-differential factory, and the double-derivation gate exists because
  even two honest parsers of one schema disagree at the edges. Signing the
  exact stored bytes and verifying the exact received bytes removes the
  entire class: there is nothing to normalize, so there is nothing to
  exploit in the normalizer.
- Why a value ratchet instead of only a revision counter. Revisions alone
  protect the signed lane but leave the unsigned restriction lane replayable
  (push the old baseline back after the user restricted). Ratcheting on the
  applied values closes that with state the extension already knows how to
  protect, and it makes the security statement local: a pinned extension
  never gets more permissive without a fresh signature, full stop (an
  unpinned one has the window-approval bound of decision 3 instead).
- Why the touched set lives inside the signed bytes instead of beside
  them. Outside the signature it would be a frame field, and a frame
  field on this channel is attacker-writable: a substituted host could
  pair a genuine fresh signature with a widened set, or none, and turn
  one tapped edit into a blanket relaxation warrant over the overlay.
  Inside the signed bytes it is exactly as trustworthy as the baseline it
  scopes, for the same reason.
- Why restrictions are unsigned at all. Requiring a tap to turn a
  confirmation ON would invert the friction symmetry every prior record
  keeps (removal is free, restoration proves presence), and would teach
  users that Touch ID sheets appear for routine tightening, which is exactly
  the reflex tap-phishing needs.
- Why the extension recomputes directions instead of trusting a signed
  "this is a restriction" bit. The signed baseline is trustworthy, but the
  unsigned overlay is not, and a direction bit inside an unsigned frame is
  an attacker-controlled claim. The direction table is contract material;
  evaluating it locally costs a loop over fields.
- Why language is excluded from the document. Bundling it would either put
  a Touch ID tap behind a language switch (hostile UX for zero security) or
  force a second unsigned lane inside the signed document (complexity in
  the one artifact that must stay simple). A separate lane with a nuisance
  ceiling is honest about what language is.

## Consequences

### Positive

- Policy has one owner, one enforcement contract, and two editing
  surfaces (the app and the signed CLI) behind one grant primitive, and
  wherever a pin exists the grant direction is hardware-gated end to end:
  the tap that ADR-0031
  requires for a grant now produces the very artifact the extension
  enforces.
- The substituted-host residual does not widen. A forged push can restrict,
  annoy, or switch languages; it cannot enable a tool, silence a
  confirmation, or extend a grace window on any pinned extension.
- The policy schema joins the ADR-0028 single source, with generated TS,
  direction metadata under cargo test, and no envelope change.
- Settings stop being per-profile by accident: two browsers on one machine
  now share one policy, which is what "the machine's owner decides what the
  bridge may do" always meant.

### Negative / accepted

- Grants cost a Touch ID tap and, on a fresh machine, pairing before any
  policy relaxation at all. That is the design, but it is new friction, and
  on unpinned machines the grant approval is an extension-window
  confirmation rather than hardware, named in decision 3.
- A reinstalled extension (empty ratchet) accepts the current signed
  baseline including grants later removed only by unsigned restriction;
  durable tightening needs one tap to re-sign. Named in decision 3.
- The #32 cold-start window now also covers the policy ratchet, and
  `policy.json` is one more same-user-writable file whose tampering is a
  fail-closed DoS.
- Users who never open the desktop app or grant through the CLI keep
  defaults only: previously
  relaxed settings (an enabled `page_upload`, a disabled confirmation) stop
  working after cutover until re-granted. The import flow
  reduces this to one tap, but the tap is mandatory.
- An old host plus a new extension stays on legacy local policy silently
  (advice-level UI nudge only). Accepted because it is exactly the shipped
  current behavior, and refusing to operate would punish users for a skewed
  update order we created ourselves.
- Two enforcement points (host dispatch and extension gate) can disagree
  transiently around a policy change; the extension's gate is authoritative
  at its boundary and the disagreement window is one push.
- Post-cutover, every new host connection costs one policy push before the
  first op dispatches, and a policy-capable host that goes silent makes the
  bridge refuse. Both are the barrier working as designed, and both are
  latency or availability costs, never capability ones.

## Implementation plan

Five phases, each landing green through `just ci` and each honoring the
browser-safety rules: browser suites only against an isolated Chrome for
Testing via `CHROME_BIN`, and every runtime-behavior claim (service worker,
reconnect, storage semantics) verified there rather than from static checks.
The Touch ID paths cannot run in CI at all; they extend the
`just touchid-gates` runbook and are verified by a human with a finger.

### Phase 1: core policy module and protocol (docs/core, no behavior shift)

`policy.rs`: `PolicyDoc` (schema, defaults, `deny_unknown_fields`,
versioned, carrying `revision` and the producing write's `touched` set
inside the signed bytes, decision 3), the direction table, the comparison
(`relaxes`, `restricts`)
anchored on the effective policy, the store (atomic, runtime-locked,
fail-closed reads), the `set_signed` / `restrict` seams (`set_signed`
embeds the caller-named touched-field set into the document before
validating and signing, obtains presence
through the sign-as-presence primitive, decision 3, and
never accepts a pre-made attestation; `restrict` takes none), the
`chromium-bridge-policy-v1` signing message. New control-frame variants
(`policy_get`, `policy_current`, `legacy_settings`, `lang_get`, `lang_set`,
`lang_current`), classification in `classify_nm_frame`, membership in
`host_control_type`. `just gen` emits `policy.gen.ts` (validator, defaults,
directions). Tests: cargo units for the direction totality rule and the
`hostReverifyMs` custom order specifically (the one a numeric comparator
gets backwards), the JS-safe revision bound, the touched-set embedding
(the signed bytes carry exactly the caller-named set, and the verify side
reads the same set back from the same bytes), the overlay fold (a
`set_signed` carrying the effective values with the folded fields as its
touched set leaves the effective policy unchanged and empties those
overlay entries), store round-trips and tamper
reads, signing-message injectivity; proptests for the comparison lattice
(relaxes/restricts are mutually exclusive given a change, reflexive-safe,
field-order independent) and revision monotonicity; the
frame-classification and server-leg-drop units in protocol.rs and
native_host.rs; the e2e frame-routing test proving the new frames are
host-answered and never forwarded; a cargo test pinning that
`check-envelope` inputs are unchanged; and, pinning the decision 8
old-extension assumption before anything relies on it, a vitest unit that
the pre-cutover extension frame router ignores an unrecognized push frame
without tearing down the port.

### Phase 2: host store, dispatch check, and the app UI

Native host answers the policy and language frames, pushes on connect and
on store changes (riding the existing revocation-watch tick), and refuses
extension `kill_release`. `revoke` and `pair --reset` clear the signed
baseline in the same critical section that deletes the key (decision 3).
`mcp_server` dispatch refuses grant-gated and
disabled tools with `TOOL_DISABLED`. Desktop app: the control-tower security
page edits the document, calls `policy::restrict` freely and
`policy::set_signed` behind its confirm-then-prompt flow (validate before
any sheet), audits every transition. CLI: `policy` read and edit
subcommands over the same two seams, with the grant path refused where no
enclave key exists (decision 5), plus `doctor` rows.
Tests: cargo units for dispatch refusal, the kill_release refusal, and
the CLI grant refusal on a keyless machine; e2e
for push-on-connect and push-on-change against a live host; app unit tests
over the presence seam with the cfg(test) mock (never a real prompt, per
the presence test isolation rule); runbook additions to
`just touchid-gates` for the grant tap and the audit rung it must record.

### Phase 3: extension consumption

The extension verifies `policy_current` against the pin (byte-exact, then
strict parse), enforces the ratchet, persists the effective policy in
trusted storage, snapshots the legacy settings bag into trusted storage
ahead of cutover (nothing is deleted in this phase), and swaps
`dispatch.ts`/`confirm` reads from local settings to the effective policy
behind the cutover flag (first applied policy wins, one-way). The
per-generation dispatch barrier lands here: post-cutover, ops are refused
until the connection's first policy push is processed. The unpinned lane's
window confirmation for relaxations lands here too. The fail-closed rules
apply throughout: a failed verification retains the stored effective, the
deny baseline covers only the no-stored-policy state, and a pin-mismatched
signature marks the bridge compromised, consistent with ADR-0031. Tests:
vitest over fakeBrowser for the full fail-closed matrix (no policy, bad
signature, wrong key, replayed lower revision, relaxation without fresh
signature, a higher-revision baseline relaxing a field outside its signed
touched set refused - the overlay-strip replay of decision 3 - while the
same baseline relaxing only its touched fields applies, forged
restriction accepted, forged relaxation refused, failed
verification retaining the stored effective rather than reverting to
defaults, the unpinned window lane approving and denying, the first
baseline verified under a fresh ratchet scope applying as-is - the deny
fallback is enforced until then but is no stored effective for the
ratchet to anchor on), ratchet
persistence across SW restarts, barrier ordering (an op racing the first
push is refused), never-speak-first against a host that pushes nothing,
and cutover one-wayness, plus the decision 8 unknown-push pin re-asserted
over the new router (an unrecognized push frame is still dropped, never
fatal). Flagged for isolated-browser verification
(`CHROME_BIN`): that the ratchet and snapshot actually survive real SW
death, and that the decision 4 in-flight rule holds under a real
mid-confirmation push.

### Phase 4: migration and language sync

`legacy_settings` send-once from the snapshot (only after a policy push
has identified a capable host), pending-import store host-side, the app's
first-run import screen signing revision 1 (on an enrolled Mac; on an
unenrolled one, floor-confirmed and stored unsigned, decision 8),
immediate overlay application of imported restrictions, `uiLanguage`
adoption at first pairing, and the
sequence-suppressed propagation on both surfaces. Tests: vitest for
send-once semantics, the capable-host gate, and echo suppression (a full
set-push-apply cycle emits exactly one `lang_set`); cargo units for
pending-import lifecycle and the never-applied rule; e2e for the language
round trip through a live host; app tests for the import screen's
tap-then-sign path over the mocked seam and for its floor-confirmed
unsigned branch. Isolated-browser: the language
change round trip extension-to-app and back, in all three locales.

### Phase 5: cleanup

The options page loses the host-owned policy controls and the kill release
control, gaining pointers to the app; `settings.ts` drops the migrated
fields and the extension deletes them (and the snapshot, once imported)
from chrome.storage; dead locale keys go, with the key-parity and
check-cjk gates keeping the three locales honest; architecture.md section
11, compatibility.md, operations.md, cli.md, SECURITY.md's threat model
(the new residuals of decisions 3 and 8), and the tool risk matrix
references are updated. Tests: the full `just ci`, the extension vitest
suite over the slimmed settings, and a final isolated-browser pass over
the options page.

## Implementation pointers

- `src/packages/core/src/policy.rs` (new): document, directions, store,
  signing, the watch.
- `src/packages/core/src/protocol.rs`: the six new control-frame variants,
  `classify_nm_frame`, `host_control_type`.
- `src/packages/core/src/native_host.rs`: frame handlers, connect/change
  pushes, the `kill_release` refusal.
- `src/packages/core/src/mcp_server.rs`: the dispatch policy check.
- `src/packages/core/src/enclave/`: the policy signing domain next to the
  enrollment and presence domains; baseline disposal on the revoke paths.
- `src/packages/core/src/presence/`: the sign-as-presence primitive.
- `src/packages/core/src/cli.rs` and `doctor.rs`: the `policy` read and
  edit subcommands (grants signature-only, decision 5), the doctor rows.
- `src/apps/desktop/src/`: the policy commands over the presence seam; the
  security and first-run import views in `ui/`.
- `src/apps/extension/src/lib/background/`: policy verification and the
  ratchet (new module), the `dispatch.ts`/`confirm` consumption swap,
  `enrollment.ts` for the compromised mark on pin-mismatched signatures.
- `src/packages/shared/src/policy.gen.ts` (generated), the control-frame
  validators next to `enclave.ts`, the slimmed `settings.ts`.
- `scripts/gen-ops.ts` and the `emit_contract` example: the policy emission.
