# Enrollment manual test (Touch ID path)

The presence-gated parts of the enrollment ceremony (ADR-0021) cannot run in
CI: they require a Secure Enclave, a codesigned binary, and a human at the
keyboard. Everything else about enrollment is covered by automated tests
(`cargo test` for the DER converter, challenge validation, and frame serde;
`tests/protocol/e2e.py::test_enclave_control_frames` for the host's local handling of
control frames). This script covers the rest. Run it on a Mac with Touch ID
before any release that touches `src/enclave.rs`, the control-frame filter,
or the keychain ACL.

## Prerequisites

- Apple Silicon or T2 Mac with Touch ID enrolled.
- A release build codesigned with an application identifier. The
  data-protection keychain (the only keychain that can hold Secure Enclave
  keys) rejects ad-hoc-signed binaries with `errSecMissingEntitlement`
  (-34018), so a plain `cargo build --release` artifact is expected to FAIL
  step 2 with a clear message. That failure mode is itself worth checking
  once (step 8).

Record the binary you are testing:

```sh
BIN=target/release/chromium-bridge
codesign -dv "$BIN"   # must show an identifier, not "adhoc"
```

## Steps

Each step lists the action and the required result. Any deviation is a
failure; stop and file it.

1. **Clean slate.** `"$BIN" revoke` then `"$BIN" enclave-status`.
   Status must report `key: none` and no config, and revoke must exit 0
   ("nothing to revoke" is fine).

2. **Pair mints and prompts.** `"$BIN" pair`.
   - A Touch ID prompt appears (the self-test signature). Approve it.
   - Output shows `enrolled.`, a base64 public key, and a SHA-256
     fingerprint in 4-character groups. Exit code 0.
   - `"$BIN" enclave-status` now shows the key present, the SAME fingerprint,
     and `enrolled=true granularity=session`.
   - `ls -l "$HOME/Library/Application Support/chromium-bridge/config.json"`:
     mode is `-rw-------`.

3. **Pair refuses a pre-existing key.** `"$BIN" pair` again.
   Exits 1 with a message that a key already exists and that re-enrollment
   requires `pair --reset`. No Touch ID prompt, no new key, no changed
   fingerprint in `enclave-status`. (`pair` never adopts a key it did not
   mint in that run; that is the planted-key defense, see ADR-0021.)

4. **Decline fails closed.** `"$BIN" pair --reset`, and when the Touch ID
   prompt appears, press Cancel.
   - Output says pairing was not approved and rolled back; exit code 1.
   - `"$BIN" enclave-status` shows `key: none` and no config. The declined
     ceremony must leave the machine unenrolled, not half-enrolled.

5. **Re-pair for the signing test.** `"$BIN" pair --reset` (if a key
   survived step 4, this also proves reset replaces it: the fingerprint must
   change). Approve the prompt.

6. **A challenge raises Touch ID and yields a valid proof.** With the MCP
   server running (`"$BIN"` under your MCP client, or started manually),
   send a well-formed challenge through a real native host:

   ```sh
   python3 - "$BIN" <<'EOF'
   import json, struct, subprocess, sys, time
   nh = subprocess.Popen([sys.argv[1], "--native-host"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)
   time.sleep(1)  # allow connect + handshake
   body = json.dumps({"type": "enclave_challenge",
                      "nonce": "manual-test-nonce",
                      "context": "manual-test"}).encode()
   nh.stdin.write(struct.pack("<I", len(body)) + body); nh.stdin.flush()
   n, = struct.unpack("<I", nh.stdout.read(4))
   print(json.dumps(json.loads(nh.stdout.read(n)), indent=2))
   nh.kill()
   EOF
   ```

   - A Touch ID prompt appears. Approve it.
   - The reply is `{"type": "enclave_proof", "sig": ..., "key_id": ...,
     "pubkey": ...}` where `key_id` equals the fingerprint from step 5 (strip
     the spaces) and `sig` decodes to exactly 64 bytes.
   - Nothing about this challenge reaches the MCP server (check its stderr:
     no forwarded-frame activity for it).

7. **Declining a challenge fails closed.** Repeat step 6 but press Cancel at
   the prompt. The reply must be
   `{"type": "enclave_error", "reason": "signing_failed"}`, and the host must
   keep running (a follow-up tool call still works).

8. **Revoke, then challenges fail closed.** `"$BIN" revoke`, then repeat
   step 6. No Touch ID prompt appears and the reply is
   `{"type": "enclave_error", "reason": "not_enrolled"}`.

9. **(Once per signing setup) Unsigned build fails loudly.** With an
   ad-hoc-signed build, `"$BIN" pair` must fail with the message pointing at
   codesigning/entitlements, exit 1, and leave `enclave-status` reporting
   no key. It must not silently fall back to a software key.

## Recording results

Note the date, macOS version, hardware, `codesign -dv` identifier, and
pass/fail per step in the release notes or PR description. Steps 2, 4, 6,
and 7 are the security-relevant ones; a release must not ship with any of
them failing.
