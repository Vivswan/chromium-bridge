# Security rationale

This page keeps the reasons behind the bridge's security decisions that the code cannot show: for each trust boundary, what was decided, what was rejected, and why. It does not describe the mechanisms themselves; [trust-boundaries.md](./trust-boundaries.md) owns those, and [threat-model.md](./threat-model.md) owns the residual risks. A row marked "(unverified against code)" states a recorded reason that no current test or source line was found to confirm.

## Harness admission and the client allowlist

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| Admission keys on the attested anchor (signing Team ID or image hash); the client name is a log label | Admit by the self-asserted client name (`CHROMIUM_BRIDGE_CLIENT_NAME`) | A name is a string any process can put in an environment variable; the anchor is what the kernel and the Security framework testify to about the running image |
| A Team ID anchor is preferred wherever the client image is Team-ID signed | Pin only the exact image hash | A free Apple Development certificate re-signs about weekly and every re-sign changes the `cdhash`; a control that nags weekly gets disabled. The cost, any binary signed by that team matches, is accepted |
| The first server instance becomes the broker; later instances attach as relays | Newest-wins takeover: attest the prior server, then SIGTERM it | Takeover cannot serve several clients at once, and a SIGTERM-on-sight path could be induced by a hostile sibling. The takeover code was deleted, not kept as a fallback |
| No `clients.json` means admission is not enforced, logged at ERROR on every start | Auto-enroll the first process that spawns the server | A silent trust-on-first-use hands the slot to whichever process races first; enrollment is the user's act |
| Once enrolled, an unmeasurable identity and an unreadable allowlist both refuse | Read a damaged file as "unenrolled" | A load failure read as unenrolled fails open |
| Revoking the last client leaves an empty file that admits nobody | Delete the file when the last entry goes | An absent file is how a first install starts; "the user revoked every client" must read as locked, never as reset |
| A one-way `clients_enrolled` latch in `revocation.json` makes deleting `clients.json` alone fail closed | A cryptographic seal or a marker outside the directory | The same user who can delete the allowlist can delete any marker; the latch closes the single-file case and the two-file deletion is the named residual |
| The relay measures its own parent and reports it in the attach frame | The broker measures the harness itself | The harness is the relay's parent, not the broker's, and no kernel interface reads another process's pipe peer. The report is trusted because the relay connection already passed attestation, so it is our own binary |
| The attach reply distinguishes `Unavailable` (retry) from `Refused` (exit non-zero) | One bare socket close | Capacity and shutdown races want a retry, which may win the bind; an allowlist miss wants a fail-closed exit, not a loop knocking on a locked door |
| Connection caps and a per-relay rate limit sit behind admission | Trust an allowlisted client fully | Attestation identifies a binary, not an intention, and the broker aggregates every client's blast radius |
| The rate limiter is one token bucket per connection, reset on reconnect | A global per-harness ceiling | The bucket bounds the damage rate as depth behind admission: the effective ceiling for a compromised allowlisted harness is the bucket size times the reconnect rate, itself bounded by the handshake and attestation cost of each connection. Revocation, not the limiter, is the lever that removes trust |

## Host identity and attestation

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| A 0600 Unix-domain socket in a 0700 directory, no listening port | Loopback TCP with a random port or firewall rules | Removing the port removes the whole "any local process can connect" class at the OS layer. Windows keeps loopback TCP because std has no Unix sockets there |
| The peer UID is checked at accept, before any authentication | Rely on the 0600 mode alone | A kernel identity assertion that depends on neither the file mode, the secret, nor the HMAC; the cheapest and strongest layer runs first |
| HMAC-SHA256 challenge-response with constant-time verification | Send the secret on the wire; or TLS and signatures | The per-run secret never crosses the socket and a fresh nonce defeats replay; both peers already share a secret and are the same binary, so a MAC needs no PKI |
| The browser label is covered by the handshake MAC, computed over the nonce, a NUL byte, then the label | Carry the label as a plain field | The label keys the connection registry and appears in tool output, so it must not be alterable separately from the proof of secret knowledge |
| A peer is accepted only if it runs the same binary as the acceptor | A pinned constant, or an env-configurable list of trusted hashes | An allowlist a same-user process can set through the environment lets it append its impostor's hash; "the same binary as me" is unforgeable by construction and needs no configuration |
| Self identity is captured at startup, before bind, accept, or dial | Measure self lazily on first use | A later replacement of the binary file cannot redefine "self" and then be accepted as a matching peer |
| macOS identifies the peer by its kernel audit token and measures the running image's `cdhash` | Re-open the peer's path and hash the file | A path need not be the running image, and a pid can be reused; the audit token names the image actually executing. Linux hashes `/proc/<pid>/exe` and keeps the narrow pid-reuse race as a residual |
| Attestation is mutual | Server-only attestation | An impostor server accepted by the host could feed it forged responses or observe its traffic |
| A tool call with several browsers connected and no `browser` argument fails with `BROWSER_AMBIGUOUS` | Default to the first or last connected browser | Acting in the wrong logged-in browser is worse than making the caller name one |
| A response is delivered only on the connection generation that sent the request | Trust process-global request ids from any connection | A hostile extension in one browser could otherwise satisfy or cancel calls addressed to another |

## Revocation and the kill switch

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| The revocation epoch is a change notice; the allowlist and the keychain stay the authority | An epoch that itself grants or denies | A same-user writer who can edit the file could then grant trust; as a notice, the worst case is a spurious re-check or a corrupt read that fails closed |
| The epoch is compared for inequality, not order | Re-decide only when the counter advances | A tamperer can write any value; a file rolled back to an older epoch still forces a re-decide, so lowering the number cannot suppress a revocation |
| A per-request guard plus a one-second watcher that re-decides idle relays unconditionally | Either mechanism alone | The guard fires only when the harness sends something; the watcher bounds an idle connection and does not depend on the counter advancing at all |
| The genuine host pushes `enclave_revoked` only when a revocation was recorded AND the keychain confirms the key is gone | Push on the revocation file alone | A scribbled file would turn the real host into the messenger for a forged compromised mark |
| The extension's key-deletion request is stored and re-sent until the host acknowledges it; pinning a fresh key supersedes it | A best-effort send at revoke time | MV3 kills the service worker and the host with it, so a lost frame would leave the old key alive |
| The kill latch lives in `revocation.json` and is the one field that IS an authority | A separate `kill.json` | The record already has the fail-closed read, the atomic write, and the tamper analysis; latch and epoch bump land in one write, so no reader sees one without the other |
| A killed harness gets the typed `BRIDGE_KILLED` refusal while the browser leg is severed | Drop the harness connection | Dropping severs the messenger and invites blind respawning; the dangerous capability is the browser leg, and that is what gets cut |
| A host that starts while killed runs a control-plane mode instead of exiting | Refuse the browser attach and let the host exit | The extension respawns the host every two seconds, so a kill would become a crash loop whose only exit is the CLI; control-plane mode keeps status and engage reachable |
| Nothing clears the latch on its own; release demands proof of presence while engage is one action | Clear on timeout, restart, or reconnect | Release is the one act that restores capability wholesale; a spurious kill costs one authenticated release, and the brake must stay one action away |
| Engage and release both refuse on an unreadable record | Rebuild a corrupt record | Replacing a corrupt security record would mask tampering, and an unkill from a state you cannot read would fail open; recovery is manual |
| The extension's kill mirror allows on absent and refuses on malformed | Treat an absent mirror as killed | A fresh install has never heard from a host and the host enforces regardless; garbage where a record should be is evidence someone wrote there |
| The extension pulls `kill_status` on every port connect and the host pushes on every transition | Push only | A CLI release while the service worker slept would otherwise leave a stale killed mirror; the push flips the mirror promptly while a port is up |
| Audit records are written after the decision and a failed write never fails the decision | Block the decision on the trail | An attacker who fills the disk must not hold enforcement hostage, and the trail must not become fail-open either; dropped records surface as a counter on the next record |
| The audit file is strict JSON lines with one rotation | Reuse the stderr log format | A reader must parse records strictly across versions, and one rotation bounds the file without a daemon |
| `kill_release` from the extension is refused and audited; engage stays on every surface | Keep the options-page release toggle | Release moved to the strongest gate available, the CLI's presence check, and the extension keeps only the capability-reducing direction |

## Enrollment and user presence

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| The host identity is a Secure Enclave key whose ACL requires user presence | A file secret | Every file a host process can read, any same-user process can read; the Enclave key can only be used, and every use prompts |
| `pair` completes only with a key it minted in that run; an existing key makes it refuse and point at `pair --reset` | Adopt whatever key sits under the label | A same-user process can plant a key, even an Enclave key without a presence ACL, and the public API cannot read an ACL back |
| Every later key lookup refuses unless exactly one key sits under the label and it carries the Secure Enclave token id | Take the first matching key | A planted software key, or a duplicate label, yields `key_invalid` instead of a signature. A single attacker-minted Enclave key under the label passes lookup (its ACL cannot be read back) and is caught by the extension's pin verification instead |
| The user compares the fingerprint printed by `pair` with the one the extension shows | Trust the first proof the extension receives | The out-of-band comparison defeats a man-in-the-middle host standing between the two |
| Signed messages are domain-prefixed and NUL-separated, under three distinct domains (enrollment, presence, policy) | One message format for every statement | The prefix stops cross-protocol replay and the separators make the encoding injective, so a proof of one statement type can never replay as another |
| Nonce and context are length-bounded and NUL-free, validated before the keychain is touched | Validate after signing, or not at all | A NUL inside a field would break the injectivity the separators provide, and malformed input must never be able to raise a presence prompt |
| The host keeps no replay state; the extension mints each nonce from a cryptographic RNG, uses it once, and accepts a proof only for the exact nonce it issued | Host-side replay tracking | The host respawns with every service worker and a file it could read, any same-user process could read; freshness is only provable where the nonce was minted |
| A per-action presence challenge binds the digest of exactly that confirmation's kind, origin, and detail | Sign a bare nonce | A tap for one action can never be replayed to approve another |
| Key deletion (`revoke`, and the delete step of `pair --reset`) is not presence-gated; the fresh mint that follows a reset still ends in the presence-gated self-test | Prompt before deleting the key | The keychain cannot bind deletion to the usage ACL, and deletion only reduces capability, so a prompt would add friction without a guarantee |
| `config.json` records enrollment state for diagnostics only; the keychain ACL and the extension's pin are the enforced decisions | Treat the config file as an authority | A same-user edit changes what `enclave-status` prints and nothing more; claiming otherwise would be a boundary enforced by assumption |
| User presence is a Secure Enclave signing operation | LocalAuthentication's `LAContext.evaluatePolicy` | Measured to return success without any fresh user interaction when the session was already authenticated, so it proves ownership, not presence |
| The presence ladder never falls from a refused hardware check to a softer floor | Fall back to an interactive confirmation when the prompt fails | An attacker who can make the prompt fail must not thereby downgrade the gate; only genuine unavailability reaches the floor |
| A non-terminal stdin is refused before any hardware prompt is raised | Prompt first, then check the terminal | A background script must not be able to flash an unexplained Touch ID sheet at the user (tap phishing); `echo release \| chromium-bridge unkill` cannot reopen the bridge |
| A presence proof that fails verification marks the bridge compromised | Treat it as a plain denial | It is evidence that the signer is not the pinned host |
| Per-action Touch ID is a policy field; enrollment itself is mandatory | An opt-out `requireEnrollment` setting | The pin, the signatures, and the presence gates all hang off enrollment, so an off switch is a footgun; the field was retired |
| Presence is not demanded on every host respawn | Verify presence at each reconnect | MV3 respawns the host about every five idle minutes, a prompt that often would be disabled, and any silent credential can be exercised by any same-user process; the residual is named in the threat model |
| For `page_eval` and `page_upload` on an enrolled Mac with `touchIdConfirm` on, the window is display-only and Deny stays | Keep an Allow button beside the tap | The tap is the only approval; refusing is the friction-free direction. With the field off, the two kinds return to the ordinary window confirmation |

## Policy signing

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| Policy that grants capability is signed by the enrollment key; policy that only restricts travels unsigned | Apply whatever the port says; or sign restrictions too | A substituted host could otherwise push `pageEvalEnabled: true, confirmPageEval: false` and turn drive-with-confirmations into silent control; signing restrictions would teach users that sheets appear for routine tightening, the reflex tap phishing needs |
| The host signs the exact stored bytes and the extension verifies the exact received bytes | Canonicalize the JSON before signing | Canonicalization is a parser-differential factory; with nothing to normalize there is nothing to exploit in the normalizer |
| The `touched` field set lives inside the signed bytes | A frame field beside the signature | A frame field on this channel is attacker-writable; a fresh signature must never become a blanket relaxation warrant over the overlay |
| The extension keeps a value ratchet; a relaxation needs a strictly higher revision whose signed `touched` set names the field | A revision counter alone | Revisions protect the signed lane but leave the unsigned restriction lane replayable: push the old baseline back after the user restricted |
| Verification keys on the extension's own pin; a key id in the frame is ignored | Honor a frame-supplied key id | It would hand a substituted host a ratchet-reset lever |
| A push that fails any check changes nothing; the stored effective policy stays | Fall back to defaults on a bad push | Defaults can be more permissive than a restricted effective policy, so "garbage in, defaults out" is a relaxation lever made of garbage |
| On an unpinned machine a relaxation waits for the user's window approval and the revision is not enforced | Enforce the revision ratchet on unsigned documents | An unauthenticated `revision = MAX` restriction would deny every later push forever, with no pairing ceremony on that machine to reset it |
| After a pin is revoked its policy record is retained, and no unsigned document may replace it until a re-pair disposes of it | Let the unpinned lane overwrite the record | The retained record is the anti-replay anchor for a same-key re-pair; an approved unsigned push erasing it would let an old, more permissive signed baseline replay after re-pairing. The cost is a policy-frozen window between revoke and re-pair |
| Once a first policy has ever applied (the cutover), bridge ops are refused until the connection's first policy push has verified | Run on the cached policy until the push lands | The port is duplex, so an op can race ahead of the push; and if garbage opened the gate, a substituted host would send garbage |
| Grants are signed with the enrollment key | A second signing key | A key without a presence ACL authenticates only the channel, and a second presence-gated key doubles the ceremony surface for no new property |
| The CLI's grant path exists only as the signature and is refused where no Enclave key exists | A typed-confirmation floor for CLI grants | A floor-gated CLI grant would quietly create a baseline-writing path on every platform the CLI ships to |
| The display language is outside the signed document | Bundle it into the policy | A Touch ID sheet behind a language switch is hostile for zero security; a forged `lang_current` is a nuisance with no capability attached |
| `revoke` and `pair --reset` clear the signed baseline in the same step that deletes the key | Keep pushing the old baseline | A baseline signed by a dead key would manufacture the very pin mismatch that means "compromised" |
| A decision in flight completes under the policy it started with | Apply a new policy immediately | A push arriving mid-confirmation cannot relax or alter that decision |

## MCP server behavior

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| The MCP layer runs on the official `rmcp` SDK and tokio, wrapped by our own gates | Teach the hand-rolled handler the stateless revision | Re-implementing a released spec next to the official SDK buys audit surface instead of reducing it; admission, the kill check, the audit record, and stderr-only diagnostics stay outside the SDK |
| A connection opened with `initialize` is served the previous revision (the legacy era) | Modern-only from day one; or a permanent dual era | Modern-only bricks a harness that still opens with `initialize`; a permanent dual era is two message sets and two-era dispatch forever |
| The legacy era is removed on an observed criterion: the harness interop smoke shows our harnesses opening with `server/discover` | A calendar date | Our own harnesses must have moved before the opening they use is refused |
| There is no bare `server/discover` probe without `_meta` | Serve the `_meta`-less probe as a leniency | The SDK has no such form and its served behavior is the source of truth; a client learns the supported set from any `-32022` error |
| Cacheable results carry `ttlMs: 3600000` and `cacheScope: "private"` | "Until the binary changes"; or `public` | The catalogue is static per binary, so one hour bounds staleness across an upgrade; `public` only buys shared caches a local attested stdio server does not have |
| KNOWN GAP: a `tools/call` with malformed params (missing `name`, non-object `arguments`) is refused by `rmcp` with `-32601` before our handler runs, so no kill check and no audit record fire for it | None; recorded | No browser action is possible on that path, and the trail records well-formed tool calls only (unverified against code) |
| `-32022` echoes the unsupported version string verbatim, bounded only by the serve loop's line cap | Fork the SDK's error shape locally | The echo is a 1:1 reflection, never amplification, pinned by the adversarial suite; an upstream issue is the follow-up |
| The Rust core is the canonical contract and the TypeScript side is generated from it | TypeScript-canonical Zod schemas | The wire contract is enforcement-core material and must not live in the tier that carries no security weight |
| Envelope parity is checked by double derivation with named erasure rules | One derived schema replacing the hand-written one | Two honest parsers of one schema disagree at the edges; each rule erases exactly one documented asymmetry, and anything outside the list fails CI |

## Native-messaging protocol

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| Control frames are answered by the host and never forwarded; the same types arriving from the server leg are dropped | Forward every frame | A misbehaving or substituted MCP server could inject `enclave_revoked` or `policy_current` down the server leg |
| The extension never sends a policy or language frame until the host has pushed one of that family on the connection | Send on connect | An old host classifies an unknown type as forwardable, and the server's strict envelope parse then tears the browser leg down |
| New host-handled frames do not bump `BRIDGE_PROTOCOL_VERSION`; a change to `BridgeReq` or `BridgeResp` does | Bump on every addition | The frames are additive and host-handled, while the envelopes reject unknown fields, so a new envelope field is breaking by construction |
| `run.lock` is parsed leniently; every other on-disk record rejects unknown fields | Strict parsing everywhere | The lock is the one file an older build reads while a newer broker writes it, and it is discovery, not authorization. A change old readers must not survive gets a new, versioned filename, so they see no lock and fail closed |
| `audit_event` from the extension is kind-whitelisted and the host stamps `surface: extension` itself | Accept any audit kind from the browser leg | The browser leg cannot forge an admission or a kill into the trail |
| On Windows the manifest launches the executable directly, and the `chrome-extension://` origin Chrome appends to argv selects host mode | A wrapper script | Windows manifests cannot carry arguments; the consequence is that every Windows browser shares the default label |
| The host converts the Security framework's DER signature to the raw 64-byte form (`r` then `s`) | Parse DER in the extension | Keeps the extension's crypto surface to one `crypto.subtle.verify` call, and the host-side parser is strict DER |

## Extension gates and tool scope

| Decision | Rejected alternative | Why |
| --- | --- | --- |
| Confirmations render in an extension-owned window | Harden the in-page toast with a closed shadow root or a nonce | The page owns its DOM and its event loop; any surface rendered into it is reachable by it |
| The router accepts `confirm_ready` and `confirm_resolve` only from the exact `/confirm.html` pathname | A URL prefix or an origin check | A prefix admits `/confirm.htmlfoo`, and some URL parsers render a `chrome-extension://` origin as `null` |
| Trust state is confined with `setAccessLevel(TRUSTED_CONTEXTS)` and the router refuses every sender that is not an extension page | The storage restriction alone | The router is a mediated path to the same state (`add_allow`, `get_enrollment`); the sub-millisecond cold-start window is the named residual |
| The approved origin and target descriptor are re-asserted in the page atomically with the act | Check them in the service worker only | A confirmation holds the pipeline open for tens of seconds, during which the tab can navigate |
| With `confirmPageEval` on (the default), `page_eval` reconfirms on every call and is excluded from the click grace window | One grace window for every confirmation kind | Two evals that one approval covers can be unrelated: `document.title`, then `fetch('/transfer')` |
| The same-origin grace window stays for submit and link clicks | No grace window at all | Repeated clicks are similar and visible in the UI; the residual is named in the threat model |
| `cookie_get` and `storage_get` exist; `cookie_set`, `cookie_remove`, and `storage_set` do not | Writes behind a high-risk confirmation | `cookie_set` can forge httpOnly plus Secure cookies (session fixation), which even page XSS cannot, and a planted cookie is invisible in a way a click is not |
| Sites are approved per origin through `optional_host_permissions` and a runtime permission request | `<all_urls>` at install; or a blocklist | The install warning and least privilege; a blocklist of banks must be maintained and defaults to open |
| One page-side implementation is stringified for the CDP backend | Two hand-ported copies of the DOM logic | Mirrored copies drifted silently behind "MUST match" comments; one self-contained function cannot |
| The default snapshot walks the DOM from a content script; the authoritative accessibility tree is fetched over the debugger only by `page_snapshot_precise` or in the opt-in CDP mode | `chrome.debugger` for every snapshot | Any attach shows the "Started debugging this browser" banner on every tab, dismissable only by a launch flag, which defeats the point of an extension |
| CDP mode is an opt-in policy grant, off by default | CDP as the default backend | It bypasses page CSP and holds a persistent debugger attach |
