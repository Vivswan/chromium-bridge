# Security rationale

This page keeps the security rules whose reason the code cannot show: for each trust boundary, the rule, the design it rejects, and why. It does not describe the mechanisms or the residuals; the [trust boundaries ledger](./trust-boundaries.md) owns both. A row exists only where a future change could plausibly reintroduce the rejected design.

## Harness admission and the client allowlist

| Rule | Rejected design | Why |
| --- | --- | --- |
| Admission keys on the attested anchor (code signer or image hash); the client name is a log label only | Admit by the self-asserted client name (`CHROMIUM_BRIDGE_CLIENT_NAME`) | A name is a string any process can put in an environment variable; the anchor is what the kernel and the Security framework testify to about the running image |
| A signed client is paired with an explicit `pair-client --signer` anchor (`--this-parent` always pins the image hash); a hash anchor is for unsigned or ad-hoc builds and for Linux | Pin the exact image hash for every client | A free Apple Development certificate re-signs about weekly and changes the `cdhash` each time, so a hash anchor would need a weekly re-pair; a control that nags weekly gets disabled |
| The first process to spawn the server is never enrolled automatically | Trust on first use | A silent first-use grant hands the slot to whichever process races first; enrollment is the user's act |
| No client paired yet (`"clients": null` in `trust.json`, or no record at all) means admission is not enforced, logged at ERROR on every start; a damaged or unreadable record refuses everyone | Read a damaged file as "unenrolled" | A load failure read as unenrolled fails open |
| Revoking the last client leaves an empty list that admits nobody | Reset the list to `null` when the last entry goes | `null` is how a first install starts; "the user revoked every client" must read as locked, never as reset |

## Host identity and attestation

| Rule | Rejected design | Why |
| --- | --- | --- |
| Where attestation is compiled in, a bridge peer is accepted only if it runs the same binary as the acceptor; the per-OS state is the table in the [ledger](./trust-boundaries.md#boundary-2-rust-mcp-server---native-host--bridge-socket-ndjson) | An env-configurable list of trusted image hashes | A list a same-user process can set through the environment lets it append its impostor's hash; "the same binary as me" is unforgeable by construction and needs no configuration |
| Self identity is measured at startup, before bind, accept, or dial | Measure self lazily on first use | A later replacement of the binary file cannot redefine "self" and then be accepted as a matching peer |

## Revocation and the kill switch

| Rule | Rejected design | Why |
| --- | --- | --- |
| Admission is re-decided from a fresh read of the trust record on every request; the epoch is a change notice for the watchers, compared for inequality, never order | Re-decide only when the counter advances | A tamperer can write any value, and a bump that failed to persist leaves the counter stale, so a decision gated on the counter can serve a revoked client; a decision taken from the record itself cannot |
| A host that starts while killed stays up in control-plane mode | Refuse the browser attach and let the host exit | The extension respawns the host every two seconds, so a kill would become a crash loop whose only exit is the CLI; control-plane mode keeps status and engage reachable |
| The extension's kill mirror allows on absent and refuses on malformed | Treat an absent mirror as killed | A fresh install has never heard from a host and the host enforces regardless; garbage where a record should be is evidence someone wrote there |

## Enrollment and user presence

| Rule | Rejected design | Why |
| --- | --- | --- |
| The CLI ceremonies that grant or restore capability (`pair`, `pair-client`, `unkill`, `policy set`) refuse a non-terminal stdin before any prompt, and their presence proof is a phrase typed on that terminal | Prompt first, then check the terminal; or accept the phrase from any stdin | A background script must not be able to flash an unexplained prompt at the user; `echo release \| chromium-bridge unkill` cannot reopen the bridge |
| The host key is a software P-256 key in the OS credential store (`keyring`: the Keychain, the Credential Manager, the Secret Service), or in a 0600 file the user chose with `pair --file-store` | A hardware-bound key available on macOS alone, whose every use demanded that OS's biometric prompt | Per-use presence comes from the browser's WebAuthn authenticator on every platform, which leaves the host key one job, identifying the installation to the extension, and a software key does that everywhere; the hardware key bound presence to macOS and left Linux and Windows no grant lane. Same-user readability is the accepted narrowing |
| `--file-store` is an explicit choice, and the file's presence IS the choice; a credential-store failure is reported, never silently redirected to the file | Fall back to the file when the store errors | A store that is locked or refusing is indistinguishable from one that is absent, and a silent fallback moves the key out of the store without the user knowing |
| Presence for an act the extension asks for is a WebAuthn assertion the HOST verifies against a credential it enrolled; the extension's window may vouch only when the browser has no enrolled credential | Let the extension report which surface satisfied presence | The host is the enforcement point, and a verdict it does not verify is a bit any code on the browser side can set; a window answer for an enrolled browser would be the downgrade the presence ladder forbids |
| A credential is enrolled under one browser's label and answers only that browser's requests; enrolling another browser needs an assertion from any enrolled credential | One pool of credentials answers every browser | The act runs for the browser connection that asked, and a second browser's authenticator vouching for the first would let a profile with its own key release a switch engaged against another; the cross-browser allowance at enrollment is what lets a second browser be enrolled at all |
| The first enrollment on a machine with none is trust on first use, re-checked under the trust-record lock at the write; every later one needs an assertion from an enrolled credential | Gate the first enrollment on the CLI's terminal confirmation; or never trust on first use | On a fresh machine no credential exists to vouch, so the choice is first use or the terminal floor, and the floor would make a scriptable pty the root of trust for every browser; the lock-side re-check closes the race where two browsers both read an empty store |
| An assertion that fails verification is refused and audited and the request is consumed; the credential stays enrolled | Unenroll the credential on a failed assertion | A failed assertion is as often a stale request or a cancelled prompt as an attack, the sign counter already catches a clone of a counting authenticator, and unenrolling on failure would let anyone who can send one bad frame remove the browser's only hardware path, demoting it to the window |
| The WebAuthn verifier accepts `attestation: "none"` only, ES256 (COSE alg -7, P-256) only, and refuses an assertion whose `signCount` has not advanced when either side counts | Parse attestation formats and trust an authenticator's certificate chain; accept every COSE algorithm the key offers | The host's trust anchor is the credential key it recorded at enrollment on this machine, so an attestation chain adds parsing surface and no trust; one algorithm keeps the shipped crypto to the pure-Rust `p256` verifier already in the graph (the same crate also compiles the signing half, which the WebAuthn path never reaches because the host holds no credential private key); a stalled counter is a cloned authenticator or a replay |

## Policy signing

| Rule | Rejected design | Why |
| --- | --- | --- |
| The host signs the exact stored policy bytes and the extension verifies the exact received bytes | Canonicalize the JSON before signing | Canonicalization is a parser-differential factory; with nothing to normalize there is nothing to exploit in the normalizer |
| Policy that only restricts needs no signature and travels unsigned; only a grant costs one | Require a signature for every policy write | A presence prompt for routine tightening teaches users that prompts are routine, the reflex tap phishing needs; a forged restriction can only remove capability |

## MCP server behavior

| Rule | Rejected design | Why |
| --- | --- | --- |
| Known gap, kept: a `tools/call` whose params are malformed (no `name`, or `arguments` neither an object nor null) is refused by `rmcp` with `-32601` before our handler, so no kill check or audit record fires | Pre-parse every frame ourselves to audit it | No browser action is possible on that path, and a second parser beside the SDK adds audit surface; the trail records well-formed calls only |

## Native-messaging protocol

| Rule | Rejected design | Why |
| --- | --- | --- |
| `run.lock` is parsed leniently; a change old readers must not survive gets a new, versioned filename | Reject unknown fields in the lock file like every other on-disk record | The lock is the one file an older build reads while a newer broker writes it, and it is discovery, not authorization; with a new filename old binaries see no lock and fail closed |
