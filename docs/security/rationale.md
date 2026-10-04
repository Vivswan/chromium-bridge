# Security rationale

This page keeps the security rules whose reason the code cannot show: for each trust boundary, the rule, the design it rejects, and why. It does not describe the mechanisms; [trust-boundaries.md](./trust-boundaries.md) owns those, and [threat-model.md](./threat-model.md) owns the residual risks. A row exists only where a future change could plausibly reintroduce the rejected design.

## Harness admission and the client allowlist

| Rule | Rejected design | Why |
| --- | --- | --- |
| Admission keys on the attested anchor (signing Team ID or image hash); the client name is a log label only | Admit by the self-asserted client name (`CHROMIUM_BRIDGE_CLIENT_NAME`) | A name is a string any process can put in an environment variable; the anchor is what the kernel and the Security framework testify to about the running image |
| A Team-ID-signed client is paired with an explicit `pair-client --team-id` anchor (`--this-parent` always pins the image hash); a hash anchor is for unsigned or ad-hoc builds and for Linux | Pin the exact image hash for every client | A free Apple Development certificate re-signs about weekly and changes the `cdhash` each time, so a hash anchor would need a weekly re-pair; a control that nags weekly gets disabled |
| The first process to spawn the server is never enrolled automatically | Trust on first use | A silent first-use grant hands the slot to whichever process races first; enrollment is the user's act |
| No `clients.json` and no enrollment latch means admission is not enforced, logged at ERROR on every start; a damaged or unreadable file refuses everyone, and so does an absent file once the latch is set | Read a damaged or deleted file as "unenrolled" | A load failure read as unenrolled fails open |
| Revoking the last client leaves an empty file that admits nobody | Delete the file when the last entry goes | An absent file is how a first install starts; "the user revoked every client" must read as locked, never as reset |

## Host identity and attestation

| Rule | Rejected design | Why |
| --- | --- | --- |
| Where attestation is compiled in, a bridge peer is accepted only if it runs the same binary as the acceptor; the per-OS state is the table in [trust-boundaries.md](./trust-boundaries.md) | An env-configurable list of trusted image hashes | A list a same-user process can set through the environment lets it append its impostor's hash; "the same binary as me" is unforgeable by construction and needs no configuration |
| Self identity is measured at startup, before bind, accept, or dial | Measure self lazily on first use | A later replacement of the binary file cannot redefine "self" and then be accepted as a matching peer |

## Revocation and the kill switch

| Rule | Rejected design | Why |
| --- | --- | --- |
| The revocation epoch is compared for inequality, never for order | Re-decide only when the counter advances | A tamperer can write any value; a file rolled back to an older epoch still forces a re-decide, so lowering the number cannot suppress a revocation |
| A host that starts while killed stays up in control-plane mode | Refuse the browser attach and let the host exit | The extension respawns the host every two seconds, so a kill would become a crash loop whose only exit is the CLI; control-plane mode keeps status and engage reachable |
| The extension's kill mirror allows on absent and refuses on malformed | Treat an absent mirror as killed | A fresh install has never heard from a host and the host enforces regardless; garbage where a record should be is evidence someone wrote there |

## Enrollment and user presence

| Rule | Rejected design | Why |
| --- | --- | --- |
| The CLI ceremonies that restore or grant capability (`unkill`, `pair-client`) refuse a non-terminal stdin before any hardware prompt is raised | Prompt first, then check the terminal | A background script must not be able to flash an unexplained Touch ID sheet at the user (tap phishing); `echo release \| chromium-bridge unkill` cannot reopen the bridge |
| A presence proof that fails verification marks the bridge compromised | Treat it as a plain denial | It is evidence that the signer is not the pinned host |

## Policy signing

| Rule | Rejected design | Why |
| --- | --- | --- |
| The host signs the exact stored policy bytes and the extension verifies the exact received bytes | Canonicalize the JSON before signing | Canonicalization is a parser-differential factory; with nothing to normalize there is nothing to exploit in the normalizer |
| Policy that only restricts needs no signature and travels unsigned; only a grant costs one | Require a signature for every policy write | A Touch ID sheet for routine tightening teaches users that sheets are routine, the reflex tap phishing needs; a forged restriction can only remove capability |

## MCP server behavior

| Rule | Rejected design | Why |
| --- | --- | --- |
| Known gap, kept: a `tools/call` whose params are malformed (no `name`, or `arguments` neither an object nor null) is refused by `rmcp` with `-32601` before our handler, so no kill check or audit record fires | Pre-parse every frame ourselves to audit it | No browser action is possible on that path, and a second parser beside the SDK adds audit surface; the trail records well-formed calls only |

## Native-messaging protocol

| Rule | Rejected design | Why |
| --- | --- | --- |
| `run.lock` is parsed leniently; a change old readers must not survive gets a new, versioned filename | Reject unknown fields in the lock file like every other on-disk record | The lock is the one file an older build reads while a newer broker writes it, and it is discovery, not authorization; with a new filename old binaries see no lock and fail closed |
