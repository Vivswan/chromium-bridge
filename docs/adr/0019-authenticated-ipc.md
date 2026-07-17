# ADR-0019: Authenticated, port-less bridge IPC (UDS + peer-UID + HMAC)

- Status: Accepted
- Date: 2026-07-16
- Amends: [ADR-0002](0002-three-process-architecture-localhost-tcp.md)
  (the three-process architecture stands; only the bridge transport and
  authentication described there are replaced)
- Extended by: [ADR-0024](0024-multi-client-attested-pairing-and-broker.md)
  (harness-admission boundary + the ref-counted broker)

## Context

The MCP server and the Chrome-spawned native host are separate processes with
no parent/child relationship, so they need a local IPC channel (see ADR-0002).
That ADR chose loopback TCP plus a per-run secret in a 0600 lock file: the host
connects to `127.0.0.1:<port>` and sends `{"hello": "<secret>"}` as the first
line; the server compares it against the lock file with `==`.

Three weaknesses in that design:

1. **An open localhost port.** `127.0.0.1:<port>` is reachable by every process
   on the machine, including other local users. The only thing standing between
   an attacker and the bridge is knowledge of the secret.
2. **The secret travels in plaintext on the wire.** Anything that can observe
   the loopback connection (a debugger attached to either process, some
   sandboxes, a future proxy) sees the long-lived per-run secret and can replay
   it on a fresh connection.
3. **Non-constant-time comparison.** `s == want` short-circuits on the first
   differing byte. In principle that leaks timing an attacker could use to
   recover the secret byte-by-byte.

The threat model (docs/security/threat-model.md) already assumes a single-user
machine, but "cheap defense in depth against other local users" was an explicit
goal, and all three weaknesses undercut it.

## Decision

Replace the transport and the authentication, in three independent layers.

### 1. Transport: 0600 Unix-domain socket (was: loopback TCP)

On Unix the server binds a Unix-domain socket at `run.sock` inside the same
0700 per-user runtime directory that already holds the lock file, and chmods
the socket 0600. A filesystem socket has **no listening port** for other
processes to reach, and its 0600 mode plus the 0700 parent directory keep other
users out at the filesystem layer. The lock file now publishes the socket path
(an `endpoint` string) instead of a port.

Windows std has no `UnixListener`, so Windows keeps the loopback TCP transport
behind `cfg(windows)` and publishes `127.0.0.1:<port>` in the same `endpoint`
field. The rest of the crate is transport-agnostic via `ipc::BridgeListener` /
`ipc::BridgeStream` type aliases.

### 2. Peer identity: reject cross-user connections at accept time

Immediately after `accept()`, before any authentication, the server reads the
connecting peer's UID from the kernel (`getpeereid` on macOS/BSD, `SO_PEERCRED`
on Linux) and drops the connection unless it equals the server's own euid. This
is a single chokepoint and does not rely on any secret: a process running as a
different local user cannot get past it even if it somehow learned the secret.
(Windows keeps its prior model with no peer check.)

### 3. Authentication: HMAC-SHA256 challenge-response (was: plaintext hello)

On each accepted connection the server sends a fresh random 128-bit nonce as a
`Challenge`; the client replies with a `Response` carrying
`HMAC-SHA256(secret, nonce)`. The server recomputes the expected MAC and
verifies the client's in **constant time** using `Mac::verify_slice` (whose
comparison does not short-circuit). The per-run secret proves knowledge but is
**never sent on the wire**, and because the nonce is fresh per connection a
captured response cannot be replayed against the next challenge.

The handshake is a typed, serde-tagged enum (`Handshake::Challenge { nonce }` /
`Handshake::Response { mac, label }`). Both sides drive it over the same
buffered reader/writer that the session and the native-host pumps then reuse, so
no byte read during the handshake is lost and no handshake frame leaks into the
forwarded stream. The `label` field is reserved for a later multi-browser phase
(a client naming the browser it fronts); it is carried through the handshake and
ignored today.

## Why these choices

- **Why UDS over TCP + firewall rules or a random high port.** Removing the
  listening port removes the entire class of "any local process can connect"
  problems at the OS layer, rather than trying to make an open port safe. File
  permissions (0700 dir + 0600 socket) are a well-understood, kernel-enforced
  boundary.
- **Why peer-UID even with 0600.** Defense in depth. The peer check is a
  positive identity assertion from the kernel that does not depend on the
  filesystem mode being set correctly, on the secret staying secret, or on the
  HMAC being implemented perfectly. It is the cheapest, strongest layer, so it
  runs first.
- **Why HMAC challenge-response over sending the secret (even over UDS).** The
  secret is long-lived for the run; keeping it off the wire means a transient
  observer of a single connection learns nothing reusable. The nonce defeats
  replay. This also lets the wire be inspected/logged for debugging without
  leaking the credential.
- **Why constant-time verification.** A non-constant-time compare is a latent
  timing oracle. `verify_slice` is the standard constant-time primitive; we do
  not hand-roll `==`.
- **Why HMAC and not a signature / TLS.** Both peers already share a secret
  (the lock file), both are the same trusted binary, and there is no PKI to
  anchor. A shared-key MAC is the minimal primitive that gives authentication +
  replay resistance without new key management. `hmac` + `sha2` are RustCrypto
  crates under MIT OR Apache-2.0 (whole transitive tree included), within the
  existing `deny.toml` allow-list.

## Consequences

### Positive

- No localhost port exists for a local process to connect to (Unix).
- A different local user is rejected by the kernel at accept time.
- The per-run secret never crosses the socket; single-connection capture is
  useless, and replay across connections fails against the fresh nonce.
- Verification is constant-time.

### Negative / costs

- Two new dependencies (`hmac`, `sha2`) and their small RustCrypto trees.
- One extra network round-trip (challenge then response) per connection, on a
  local socket, at connect time only. Negligible.
- Windows does not get the port-less transport or the peer check (no std UDS);
  it keeps the prior loopback-TCP + secret model. The HMAC handshake, being
  transport-independent, does apply on Windows.
- `doctor` and `tests/protocol/e2e.py` had to learn the new `endpoint` field and the
  handshake; the mock extension now computes the HMAC.

### What remains irreducible (accepted)

- **Same-user malware.** A process running as the *same* user can read the 0600
  lock file, learn the secret, pass the peer-UID check, and complete the
  handshake. None of these layers defend against code already running as you
  with filesystem access to your runtime directory; that is out of scope per the
  threat model (single-user machine; a same-UID hostile process is not defended
  beyond raising the bar). The layers here raise the cost for *other* users and
  for passive observers, not for an attacker who already is you.
- A compromised OS account or a malicious MCP client the user configured remain
  out of scope, unchanged from ADR-0002 and the threat model.

## Implementation

- `src/ipc.rs`: `BridgeListener`/`BridgeStream` aliases; `listen()` binds the
  0600 UDS (TCP on Windows); `peer_uid()`; `server_handshake()` /
  `client_handshake()` with constant-time `verify_mac`; `LockFile.endpoint`.
- `src/mcp_server.rs`: peer-UID chokepoint in the accept loop.
- `src/session.rs`: `attach_connection` runs `server_handshake` before
  installing the writer.
- `src/native_host.rs`: `client_handshake` before the pumps start; old hello
  filter removed.
- `src/protocol.rs`: the typed `Handshake` enum.
- `tests/protocol/e2e.py`: mock extension connects over the socket and answers the HMAC
  challenge; verified end-to-end including real `--native-host` mode.
