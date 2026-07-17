# ADR-0020: Kernel-attested peer executable identity for the bridge

- Status: Accepted
- Date: 2026-07-16
- Extends: [ADR-0019](0019-authenticated-ipc.md) (adds a check; the UDS +
  peer-UID + HMAC design there stands unchanged)

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

1. **Peer PID from the kernel.** On a connected Unix-domain socket, read the
   peer's PID: `SO_PEERCRED` on Linux (the same struct that carries the UID),
   `LOCAL_PEERPID` via `getsockopt(SOL_LOCAL, ...)` on macOS. This is kernel
   testimony, not a self-reported value.

2. **Resolve and hash the peer's on-disk executable.** On Linux, hash
   `/proc/<pid>/exe`; on macOS, resolve the path with `proc_pidpath` and hash the
   file. SHA256, streamed.

3. **Require it to equal our own executable's hash.** We hash our own image by
   the identical mechanism (`/proc/self`-equivalent for our PID), cached once.
   The "trusted-identity allowlist" is therefore exactly `{our own binary}`: a
   peer is accepted only if it is another instance of the same bytes.

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

- **Self identity is captured at startup.** `own_exe_hash` is primed by
  `ensure_own_identity` at process start, before we bind, accept, or dial, so our
  notion of "self" reflects the genuine on-disk binary. A later replacement of
  the binary file cannot redefine "self" and then be accepted as a matching peer.

- **SHA256 now; macOS is best-effort until code-signing.** The task considered
  SHA256 or a macOS code-signature / Team-ID check (`SecStaticCodeCheckValidity`).
  We ship SHA256-of-self because it works on both Linux and macOS today and its
  accept path is testable. **On macOS it is not fully enforced**, though: with no
  `/proc`, we resolve the path with `proc_pidpath` and re-open it, which is not
  bound to the running image. Startup self-capture defeats the simple
  "replace-the-binary-then-run-it" bypass (the replacement no longer matches our
  captured self hash), but the deeper problem remains: the path contents need not
  represent the running image at all. A peer can `exec` a malicious image from an
  inode and then leave (or restore) the genuine binary at the path it reports, so
  when we open that path we hash the genuine bytes while other code runs.
  Fully closing this needs a running-image-bound API: `SecCode` validation *by
  pid* (`SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` against a
  designated requirement, or comparing the kernel-reported cdhash), which is both
  stronger and TOCTOU-safe. That is the macOS follow-up and should replace the
  path-rehash; a code-signature check is also only meaningful once the binary is
  Team-ID signed, and the signing pipeline is not yet in place.

- **Plain comparison of the two digests.** Unlike the HMAC tag (a secret,
  compared in constant time), the executable hashes are not secrets, so a
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
- On Linux the bridge speaks only to another instance of itself in both
  directions, subject to the narrow pid-reuse race noted above. On macOS this is
  best-effort (the path re-open is not running-image-bound); see the residuals.
- The e2e suite is more realistic: round-trips flow through a real
  `--native-host` subprocess, and an adversarial test
  (`test_foreign_peer_is_rejected`) asserts a raw non-binary peer is dropped
  without a challenge.

Negative / accepted:

- The e2e tests can no longer impersonate the extension by connecting to the
  socket from Python; they must spawn the real host binary. This is a direct
  consequence of the check working, and we did **not** add a test-only bypass
  (that would violate the zero-trust "never weaken a check" rule).
- On macOS the check is **best-effort, not fully enforced**: the path re-open is
  not bound to the running image, so it does not achieve the same guarantee as
  Linux until the `SecCode`-by-pid follow-up lands (see "Why these choices").
- Pid resolution can race with pid reuse if a peer exits mid-connection after
  passing its descriptor to another process (narrow; see "Why these choices").
- Windows (loopback TCP) and non-Linux/macOS Unix are not attested, consistent
  with ADR-0019's peer-UID posture, which is also Unix-only.

Irreducible (named honestly, per the zero-trust principle):

- A same-user attacker who **re-executes our own binary** (`browser-bridge
  --native-host`, or a copy of it) is byte-identical to the legitimate host. No
  executable hash, and no code signature, can distinguish "the host the browser
  spawned" from "the same binary an attacker ran." Closing that requires binding
  trust to the browser/extension side (the native-messaging manifest already
  limits which extension can spawn the host, and a trust-on-first-use pairing in
  the extension settings would bind a per-install approval). That work is tracked
  separately; this ADR does not claim to cover it.

## Implementation pointers

- `src/ipc.rs`: `peer_pid`, `exe_hash_of_pid`, `own_exe_hash`, `attest_peer`,
  `identities_match`.
- `src/mcp_server.rs`: accept loop attests the host after the peer-UID check.
- `src/native_host.rs`: attests the server right after `connect`.
- `tests/e2e.py`: round-trips route through a real `--native-host` process;
  `test_foreign_peer_is_rejected` covers the reject path.
