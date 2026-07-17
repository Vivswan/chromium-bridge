# ADR-0020: Kernel-attested peer executable identity for the bridge

- Status: Accepted
- Date: 2026-07-16
- Extends: [ADR-0019](0019-authenticated-ipc.md) (adds a check; the UDS +
  peer-UID + HMAC design there stands unchanged)
- Extended by: [ADR-0024](0024-multi-client-attested-pairing-and-broker.md)
  (harness-admission boundary + the ref-counted broker)

## Context

ADR-0019 removed the listening port, rejected other local users with a kernel
peer-UID check, and authenticated the bridge with an HMAC-SHA256
challenge-response over a per-run secret. That closes cross-user attacks and
guards the secret on the wire.

It does not close one gap. The per-run secret lives in a 0600 lock file owned by
our own UID. Any process running as the same user can read that file, so any
same-user process can complete the HMAC handshake and drive the bridge. The
peer-UID check does not help here: the attacker *is* the right UID.

The project's security principle (AGENTS.md, "zero trust") is explicit that a
boundary must be enforced by an unforgeable mechanism, not by "hard to guess" or
"can read a file," and states the goal as a Codex-level non-abuse guarantee:
another program you are running must not be able to use this bridge silently.
"Can read the lock file" is exactly the kind of non-enforcement that principle
rejects.

## Decision

Before authenticating, each end **kernel-attests the other's executable
identity** and serves the connection only if the peer is running the same binary
as itself.

1. **Ask the kernel who the peer is.** On a connected Unix-domain socket, take a
   kernel-attested identity for the peer: `SO_PEERCRED` (the pid, in the same
   struct that carries the UID) on Linux; the **audit token** via
   `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)` on macOS, falling back to
   `LOCAL_PEERPID` only if the audit token is unavailable. Either way this is
   kernel testimony, not a self-reported value.

2. **Measure the peer's running image.** On Linux, hash `/proc/<pid>/exe` (the
   kernel's magic symlink to the running inode) with streamed SHA256. On macOS,
   obtain a `SecCode` for the peer with `SecCodeCopyGuestWithAttributes` keyed on
   `kSecGuestAttributeAudit` (the audit token), validate its running signature
   with `SecCodeCheckValidity`, and read its code-directory hash (`cdhash`, key
   `kSecCodeInfoUnique`). The audit token names the *running* image, so the macOS
   measurement is bound to the process actually executing, not to a re-openable
   path.

3. **Require it to equal our own image's measurement.** We measure ourselves by
   the identical mechanism (`/proc/self`-equivalent on Linux; `SecCodeCopySelf`
   then cdhash on macOS), cached once. The "trusted-identity allowlist" is
   therefore exactly `{our own binary}`: a peer is accepted only if it is another
   instance of the same code.

4. **Fail closed, mutually.** On mismatch or any inability to establish the
   peer's identity, drop the connection and log to stderr. The server attests the
   host right after `accept` (before the HMAC handshake); the native host attests
   the server right after `connect` (before it speaks the handshake or forwards a
   frame).

## Why these choices

- **Allowlist-of-self, not a pinned constant or config file.** Both bridge ends
  are the same `browser-bridge` binary in different modes, so "the peer must be
  the same binary as me" is the natural, correct identity and needs no
  configuration. It also keeps development and CI working: an unsigned, freshly
  built binary still matches itself, because both ends are that same build.

- **No environment-configurable allowlist (e.g. `BB_TRUSTED_PEER_SHA256`).** An
  earlier sketch of this work considered an env or config list of extra trusted
  hex digests so a different-but-trusted build or path could be permitted. We
  deliberately did **not** add it. An allowlist a same-user process can set
  through the environment is exactly the "flag, default, or env var that bypasses
  a security gate" that AGENTS.md forbids adding without a reviewed decision: a
  hostile process that can influence how the host is launched could append its
  own impostor's hash and defeat the entire attestation. The allowlist stays
  `{our own binary}`, which is unforgeable by construction. If a concrete
  different-but-trusted-build need ever arises (say, a signed release plus a local
  dev build), it should be met by the macOS `SecCode`/Team-ID path below or by an
  explicit, ADR-recorded allowlist with a non-environment trust source, not by an
  env knob.

- **Kernel peer-PID, not a PID sent over the socket.** A PID the peer told us
  could be forged; `SO_PEERCRED` / `LOCAL_PEERPID` come from the kernel for the
  actual process on the other end of the socket.

- **`/proc/<pid>/exe` on Linux binds to the running inode.** It is a magic
  symlink to the running executable's inode; opening it reads the real backing
  file even if the on-disk path was replaced after the process started. The one
  gap is *pid resolution* itself: the pid comes from `SO_PEERCRED` (stable for
  the connection), but resolving it to `/proc/<pid>/exe` is a later step that can
  race with pid reuse if the peer exits mid-connection after passing its
  descriptor elsewhere. That window is small and the attack is sophisticated
  (fd-passing plus precise reuse timing), and to pass it the reused pid must be a
  genuine copy of our binary anyway; it is recorded as a residual, not closed.
  On macOS the audit-token path closes even this race (below).

- **Self identity is captured at startup.** `own_identity` is primed by
  `ensure_own_identity` at process start, before we bind, accept, or dial, so our
  notion of "self" reflects the genuine image (Linux SHA256 of the on-disk
  binary; macOS cdhash of the running image). A later replacement of the binary
  file cannot redefine "self" and then be accepted as a matching peer.

- **macOS: audit token + `SecCode` cdhash, running-image-bound.** Rather than
  re-opening a path (which need not represent the running image at all -- a peer
  can `exec` a malicious image from an inode and leave the genuine binary at the
  path it reports), macOS identifies the peer by its kernel **audit token** and
  measures it through the Security framework. The audit token names the running
  image, so `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit, ...)`
  followed by `SecCodeCheckValidity` verifies the code *actually executing*, and
  its `cdhash` (`kSecCodeInfoUnique`) is compared to our own
  (`SecCodeCopySelf` -> cdhash). This closes both the path re-open TOCTOU and the
  pid-reuse race in one move. cdhash is the hash of the code pages, present on
  ad-hoc-signed binaries -- and on Apple Silicon the toolchain ad-hoc-signs every
  build at link time -- so this is enforceable and testable on unsigned dev and
  CI binaries today, no signing pipeline required. If the kernel reports the
  audit-token option itself is unsupported (`getsockopt` returns `ENOPROTOOPT`,
  older systems without `LOCAL_PEERTOKEN`), we fall back to identifying the guest
  by pid (`kSecGuestAttributePid`), which is still running-image-validated by
  `SecCodeCheckValidity` but reopens the narrow pid-reuse race. Any *other*
  audit-token failure (a short read, a permission error) fails closed rather than
  downgrading. **Follow-up:** Team-ID / designated-requirement pinning
  (accepting a signing identity rather than one exact cdhash) is deferred until a
  real signing identity lands; it is what would let a signed release and a local
  build trust each other. Until then the allowlist is one exact cdhash, which is
  correct for the same-binary bridge and is what makes a *different* image
  (even a validly Apple-signed one, e.g. `python3`) fail closed. The FFI is
  hand-declared against the Security and CoreFoundation frameworks so no new
  crate enters the dependency graph.

- **Plain comparison of the identities.** Unlike the HMAC tag (a secret, compared
  in constant time), the executable hashes and cdhashes are not secrets, so a
  short-circuiting `==` leaks nothing useful.

- **Mutual, not server-only.** The host must also know it is talking to the real
  MCP server: an impostor server accepted by the host could feed it forged
  responses or observe its traffic. Both ends attest.

## Consequences

Positive:

- A *different* same-user program (malware, a curious script) is rejected at
  `accept`, before it can attempt the HMAC handshake. This is the meaningful
  raise over ADR-0019: reaching the socket and reading the secret is no longer
  enough; you must be our binary.
- On both Linux and macOS the bridge speaks only to another instance of itself in
  both directions. On macOS the audit-token + `SecCode` path is bound to the
  running image, closing the path re-open TOCTOU and the pid-reuse race; on Linux
  the `/proc/<pid>/exe` inode measurement is bound to the running image but leaves
  the narrow pid-reuse race on pid resolution (see the residuals).
- The e2e suite is more realistic: round-trips flow through a real
  `--native-host` subprocess (waiting on the host's real handshake-complete
  signal, not a fixed sleep), and an adversarial test
  (`test_foreign_peer_is_rejected`) asserts a raw non-binary peer is dropped
  without a challenge -- on macOS this exercises the full audit-token -> `SecCode`
  -> cdhash rejection of a validly Apple-signed but different binary.

Negative / accepted:

- The e2e tests can no longer impersonate the extension by connecting to the
  socket from Python; they must spawn the real host binary. This is a direct
  consequence of the check working, and we did **not** add a test-only bypass
  (that would violate the zero-trust "never weaken a check" rule).
- macOS trust is pinned to one exact `cdhash` (our own). Team-ID /
  designated-requirement pinning -- which would let a signed release and a
  separate local build trust each other -- is deferred until a real signing
  identity lands. For the same-binary bridge, one-cdhash is the correct, tighter
  policy; the deferral only means we do not yet accept a *different* trusted
  build.
- Linux pid resolution can race with pid reuse if a peer exits mid-connection
  after passing its descriptor to another process (narrow; see "Why these
  choices"). The macOS pid *fallback* shares this narrow race, but only when the
  kernel audit token is unavailable.
- Windows (loopback TCP) and non-Linux/macOS Unix are not attested, consistent
  with ADR-0019's peer-UID posture, which is also Unix-only.

Irreducible (named honestly, per the zero-trust principle):

- A same-user attacker who **re-executes our own binary** (`browser-bridge
  --native-host`, or a copy of it) is byte-identical to the legitimate host, so
  it has the same SHA256 and the same cdhash. No executable hash, and no code
  signature, can distinguish "the host the browser spawned" from "the same binary
  an attacker ran." Nor can any of this stop code injection (`ptrace`, dylib
  insertion) into the already-approved running process. Closing those requires
  binding trust to the browser/extension side (the native-messaging manifest
  already limits which extension can spawn the host, and a trust-on-first-use
  pairing in the extension settings would bind a per-install approval) and, for
  injection, hardened-runtime / Secure-Enclave-backed measures. That work is
  tracked separately (extension pairing; Stage B); this ADR does not claim to
  cover it.

## Implementation pointers

- `src/ipc.rs`: `peer_pid`, `own_identity`, `peer_identity`, `attest_peer`,
  `identities_match`; the macOS `codesign` submodule holds the audit-token +
  Security-framework FFI (`peer_cdhash`, `own_cdhash`).
- `src/mcp_server.rs`: accept loop attests the host after the peer-UID check.
- `src/native_host.rs`: attests the server right after `connect`.
- `tests/e2e.py`: round-trips route through a real `--native-host` process and
  wait on its handshake-complete signal; `test_foreign_peer_is_rejected` covers
  the reject path.
