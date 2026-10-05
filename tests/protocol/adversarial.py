"""Adversarial break-in regression suite for chromium-bridge.

The socket-level attacker's view: a hostile same-user process that connects
straight to the bridge socket, replays or forges the handshake, floods the
protocol readers, spoofs a trusted-client name, or reads the per-run secret
out of diagnostics. Every case drives the real release binary inside a private
runtime dir (harness.isolate); the drift answer each test pins is its first
docstring line.

Central fact: the broker attests a peer's executable identity BEFORE the HMAC
handshake and before forwarding any byte (src/packages/core/src/broker.rs
admit(): peer-UID -> attest_peer -> handshake). A foreign peer is dropped at
attestation with a clean EOF, so the black-box attacks here prove attestation;
the parser and MAC defenses behind it are proven by the Rust unit tests,
proptests, and fuzz targets they name below, never faked through a path an
attacker cannot reach.

Attack matrix (LIVE = asserted here; REF = covered elsewhere, named):

  A1   rogue python3 socket peer                 LIVE  dropped at attestation
  A2   byte-identical binary copy                LIVE  ACCEPTED (the accepted residual)
  A3   binary swap after launch                  LIVE  python rejected; genuine OK or fail closed
  A8   blank-line flood on the MCP stdin leg     LIVE  server still responds
  A9   over-64MB line on the MCP and NM legs     LIVE  bounded rejection, survives
  A11  no open TCP port                          LIVE  UNIX listener only
  A12  secret confidentiality                    LIVE  never leaks; doctor redacts
  A14  enrolled + non-allowlisted harness        LIVE  refused, fail closed
  A15  enrolled + spoofed client NAME            LIVE  name is not authz; refused
  A16  enrolled + genuinely paired harness       LIVE  admitted; drives the bridge
  A17  revoke-client vs a live broker            LIVE  dropped, no re-attach
  A18  revoke from the extension surface         LIVE  host-mediated, epoch bumped
  A19  deleting trust.json                       LIVE  the loud bootstrap, never silent
  A20  kill switch vs a live broker              LIVE  typed refusal at every surface
  A21  corrupt trust record                      LIVE  everything fails closed
  A22  unkill without user presence              LIVE  refused and audited
  A23  junk _meta protocolVersion values         LIVE  -32022 strings, -32602 malformed
  A24  bare discover opener + hostile flood      LIVE  opener dropped; flood served
  A25  1 MB protocolVersion string               LIVE  -32022, echo not amplified
  A4   replay a captured HMAC response           REF   unreachable past A1; ipc/handshake.rs
                                                       verify_mac_* and handshake_round_trip_over_socketpair
  A5   forged or garbage MAC                     REF   same drop; verify_mac is constant time
  A6   hex-decoder abuse                         REF   ipc/handshake.rs hex_decode tests + hex_fuzz
  A7   serde/parser abuse on arbitrary bytes     REF   protocol.rs proptests + the fuzz targets
  A10  cross-uid connect                         REF   needs a second uid; the 0700 runtime dir
                                                       and the peer-UID check in broker.rs admit()
  A13  native-messaging manifest substitution    REF   browser-gated: a substituted host fails
                                                       pairing only through the extension's
                                                       enrollment pin; needs an isolated browser

Run: `moon run test-adversarial` (or `python -m unittest discover -s tests/protocol -p adversarial.py -v`).
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import unittest

import harness as h
from harness import (BridgeCase, McpClient, Served, nm_read, nm_write, normalized, rpc_error,
                     rpc_result, tool_error, tool_result)


def setUpModule():
    h.ensure_binary()
    h.isolate("bb-adversarial-")


def tearDownModule():
    h.teardown()


TAB = [{"id": 7, "title": "Adversarial Tab", "url": "https://x", "active": True}]
FORWARDED_TAB_LIST = {"op": "tab_list", "args": {}, "browser": "default"}
MISSING_META = "request _meta is missing or has malformed required fields: "
MISSING_BOTH = MISSING_META + f"{h.META_VERSION_KEY}, {h.META_CAPS_KEY}"
ALLOWLIST_REFUSAL = "not in the trusted-client allowlist"


def copy_of_binary(name):
    """A byte-identical copy of the release binary in the isolated dir."""
    path = os.path.join(h.RUNDIR, name)
    shutil.copy2(h.BIN, path)
    os.chmod(path, 0o755)
    return path


def pair(*args, env=None):
    """Pair a trusted client through the CLI presence floor."""
    h.run_with_cli_presence(["pair-client", *args], env=env)


class AdversarialCase(BridgeCase):
    def assertRoundTrip(self, c, nh, _id):
        served = Served(nh, TAB)
        r = c.call("tab_list", {}, _id=_id)
        self.assertEqual(served.request(), FORWARDED_TAB_LIST)
        self.assertEqual(r, tool_result(_id, TAB))

    def enrolled_broker(self):
        return super().enrolled_broker(self.legacy_client)


class Attestation(AdversarialCase):
    def test_a1_rogue_python_peer_is_dropped_at_attestation(self):
        """A raw same-user process gets a clean EOF with no challenge, the
        server logs the identity mismatch, and no handshake ever started."""
        self.skip_unless_unix("executable attestation")
        srv = self.server()
        self.assertEqual(h.foreign_peer_outcome(srv.lock), b"", "no challenge sent to the foreign peer")
        h.reap(srv)
        err = h.server_stderr(srv)
        self.assertIn("peer executable identity mismatch", err)
        self.assertNotIn("bridge handshake failed", err, "the peer never reached the handshake")

    def test_a2_byte_identical_copy_is_accepted(self):
        """The accepted residual: identical bytes are the genuine binary to
        attestation, so a copy attaches and drives a full round trip."""
        self.skip_unless_unix("executable attestation")
        srv = self.server()
        c = self.legacy_client(srv)
        nh = self.host(bin_path=copy_of_binary("evil-copy"))
        self.assertRoundTrip(c, nh, 5)

    def test_a3_binary_swap_after_launch_grants_no_bypass(self):
        """Identity is pinned at startup: swapping the on-disk file still
        rejects a python peer. Linux (identity = the original inode's bytes)
        keeps admitting a genuine host from a new path; macOS (SecCode checks
        the running image against its file) fails closed to new peers."""
        self.skip_unless_unix("executable attestation")
        server_a = copy_of_binary("server-a")
        srv = self.server(bin_path=server_a)
        # A rename swaps the inode under the running server (an in-place
        # write would be ETXTBSY on Linux).
        blob = os.path.join(h.RUNDIR, "swap-b.tmp")
        with open(blob, "wb") as f:
            f.write(os.urandom(4096))
        os.replace(blob, server_a)
        self.assertEqual(h.foreign_peer_outcome(srv.lock), b"", "python peer still dropped after the swap")
        nh = self.host(bin_path=copy_of_binary("genuine-c"), ready=False)
        attested = nh.ready.wait(6)
        if sys.platform.startswith("linux"):
            self.assertTrue(attested, "a genuine host from a new path still attests")
        else:
            self.assertFalse(attested, "the server fails closed to new peers after the swap")
            self.assertIn("server attestation failed", h.host_stderr(nh))
        h.reap(nh)
        h.reap(srv)
        self.assertIn("peer executable identity mismatch", h.server_stderr(srv))


class Floods(AdversarialCase):
    def test_a8_blank_line_flood_on_the_mcp_leg(self):
        """200k blank lines are skipped in constant stack (the recursive skip
        once aborted under panic=abort) and the next real line is answered."""
        srv = self.server()
        srv.stdin.write("\n" * 200_000)
        srv.stdin.flush()
        c = McpClient(srv)
        init = self.bounded("initialize after the flood", c.initialize, 15)
        self.assertEqual(normalized(init), rpc_result(1, h.legacy_init_result()))
        self.assertIsNone(srv.poll(), "the server survived")

    def test_a9_oversize_line_on_the_mcp_leg(self):
        """A line over the 64 MB cap is rejected without buffering it whole,
        logged, and the reader keeps looping: the next initialize is served."""
        srv = self.server()
        srv.stdin.write("x" * (64 * 1024 * 1024 + 2) + "\n")
        srv.stdin.flush()
        c = McpClient(srv)
        c.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": h.LEGACY_VERSION, "capabilities": {},
                           "clientInfo": {"name": "e2e", "version": "0.1"}}})

        def read_until_init():
            for _ in range(12):
                r = c.recv()
                if r.get("id") == 1:
                    return r
            return None

        init = self.bounded("initialize after the oversize line", read_until_init, 20)
        self.assertEqual(normalized(init), rpc_result(1, h.legacy_init_result()))
        self.assertIsNone(srv.poll(), "the server was not aborted")
        h.reap(srv)
        self.assertIn("exceeds the line-length cap", h.server_stderr(srv))
        self.assertEqual(srv.returncode, 0, "a clean exit, no abort signal")

    def test_a9_oversize_frame_on_the_nm_leg(self):
        """A ~4 GB length prefix trips the inbound clamp before any allocation:
        the host rejects it and exits, the server keeps serving."""
        self.skip_unless_unix("the native host leg")
        srv = self.server()
        c = self.legacy_client(srv)
        nh = self.host()
        nh.stdin.write(struct.pack("<I", 0xFFFFFFFF))
        nh.stdin.flush()
        self.assertExits(nh, 5, "the host rejected the oversize frame (no OOM)")
        self.assertIn("frame too large", h.host_stderr(nh))
        self.assertEqual(c.ping(_id=77), rpc_result(77, {}), "the server survived the NM-leg overflow")

    def test_a25_oversized_version_string(self):
        """A 1 MB version string (under the line cap) is refused per request
        with -32022 echoing it verbatim, never amplified, with no crash."""
        srv = self.server()
        c = McpClient(srv)
        big = "9" * (1024 * 1024)
        r = self.bounded("1 MB version reply", lambda: c.modern_tools_list(_id=300, version=big), 20)
        self.assertEqual(r, h.unsupported_version(300, big))
        init = self.bounded("initialize afterwards", c.initialize, 10)
        self.assertEqual(normalized(init), rpc_result(1, h.legacy_init_result()))
        self.assertIsNone(srv.poll(), "no crash, no OOM")


class Surface(AdversarialCase):
    def test_a11_no_tcp_port(self):
        """The bridge is a filesystem socket: the listener enumerator finds the
        server's UNIX socket and no TCP listener. A missing or failing
        enumerator is a failure, never a vacuous pass."""
        self.skip_unless_unix("the UNIX-domain listener")
        srv = self.server()
        pid = srv.pid
        if sys.platform.startswith("linux"):
            self.assertIsNotNone(shutil.which("ss"), "ss is required on the Linux gate")
            tcp = subprocess.run(["ss", "-Hltnp"], capture_output=True, text=True)
            unix = subprocess.run(["ss", "-Hlxnp"], capture_output=True, text=True)
            self.assertEqual((tcp.returncode, unix.returncode), (0, 0))
            owned = lambda out: f"pid={pid}," in out or f"pid={pid})" in out  # noqa: E731
            self.assertEqual((owned(unix.stdout), owned(tcp.stdout)), (True, False),
                             "a UNIX listener for the pid and no TCP listener")
        else:
            self.assertIsNotNone(shutil.which("lsof"), "lsof is required on macOS")
            files = subprocess.run(["lsof", "-nP", "-p", str(pid)], capture_output=True, text=True)
            self.assertEqual(files.returncode, 0, files.stderr)
            lines = files.stdout.splitlines()
            has_unix = any("unix" in ln.lower() for ln in lines)
            has_tcp_listen = any("TCP" in ln and "LISTEN" in ln for ln in lines)
            self.assertEqual((has_unix, has_tcp_listen), (True, False),
                             "a UNIX socket for the pid and no TCP LISTEN")

    def test_a12_secret_never_leaks(self):
        """Under maximum log verbosity the per-run secret appears in no stdout
        or stderr (server, host, doctor, tool reply), and doctor redacts it."""
        env = dict(os.environ, BB_LOG="debug")
        srv = self.server(env=env)
        secret = srv.lock["secret"]
        self.assertRegex(secret, r"^[0-9a-f]{32}$")
        c = self.legacy_client(srv)
        reply = ""
        nh = None
        if os.name != "nt":
            nh = self.host(env=env)
            served = Served(nh, TAB)
            reply = json.dumps(c.call("tab_list", {}, _id=5))
            served.request()
        doc = h.run_cli(["doctor"], env=env)
        h.reap(nh)
        h.reap(srv)
        host_err = h.host_stderr(nh) if nh is not None else ""
        if nh is not None:
            # log.rs falls back silently to info on an unknown variable, so a
            # renamed BB_LOG would quietly weaken the hunt: demand a debug line.
            self.assertIn("[DEBUG] [", host_err, "BB_LOG=debug is live")
        captured = "".join([h.server_stderr(srv), host_err, doc.stdout, doc.stderr, reply])
        self.assertNotIn(secret, captured, "the secret appears in no captured output")
        self.assertRegex(doc.stdout, r"<redacted, \d+ chars>", "doctor prints the secret redacted")


class Admission(AdversarialCase):
    def test_a14_non_allowlisted_harness_is_refused(self):
        """Once any client is paired, admission is enforced: a harness that is
        not on the allowlist never becomes the broker and exits 1."""
        self.skip_unless_unix("harness attestation")
        h.reset_enrollment()
        self.addCleanup(h.reset_enrollment)
        pair("--name", "decoy", "--hash", "00" * 20)
        self.assertRefusedToStart(self.server(wait=False), ALLOWLIST_REFUSAL)

    def test_a15_spoofed_client_name_is_not_authorization(self):
        """Authorization keys on the attested hash: claiming a paired client's
        NAME through the env var is refused, and the refusal audit line shows
        the spoofed name reached the server."""
        self.skip_unless_unix("harness attestation")
        h.reset_enrollment()
        self.addCleanup(h.reset_enrollment)
        pair("--name", "trusted", "--hash", "11" * 20)
        # BB_LOG pinned to info: an ambient warn/error level would hide the audit line.
        env = dict(os.environ, CHROMIUM_BRIDGE_CLIENT_NAME="trusted", BB_LOG="info")
        srv = self.server(env=env, wait=False)
        self.assertRefusedToStart(srv, ALLOWLIST_REFUSAL)
        self.assertIn("name=trusted", h.server_stderr(srv))

    def test_a16_paired_harness_is_admitted_and_serves(self):
        """Enrollment must not brick a genuinely trusted client: this
        interpreter, paired by its attested identity, becomes the broker and
        drives the browser."""
        srv, c, nh = self.enrolled_broker()
        self.assertRoundTrip(c, nh, 42)


class Revocation(AdversarialCase):
    def test_a17_revoke_reaches_the_live_broker(self):
        """revoke-client rewrites the allowlist and bumps the epoch in one atomic
        write of the trust record; the live broker drops the revoked harness on
        its next request (EOF, no service), exits, and a re-attach is refused."""
        srv, c, nh = self.enrolled_broker()
        self.assertRoundTrip(c, nh, 50)
        before = h.read_trust()["epoch"]
        h.run_cli(["revoke-client", "--name", "pytest"], check=True)
        self.assertGreater(h.read_trust()["epoch"], before, "the epoch moved with the allowlist")
        c.send({"jsonrpc": "2.0", "id": 51, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        self.assertEqual(self.bounded("the revoked call", srv.stdout.readline, 10), "",
                         "the revoked harness gets EOF, not service")
        self.assertExits(srv, 5, "the broker for the revoked harness exits")
        self.assertRefusedToStart(self.server(wait=False), ALLOWLIST_REFUSAL)

    def test_a18_revoke_from_the_extension_surface(self):
        """client_list and client_revoke are answered by the host; the revoke
        rewrites the allowlist, bumps the epoch, leaves the surviving client
        serving, and a ghost name is ok:false, never a guess."""
        self.skip_unless_unix("harness attestation")
        h.reset_enrollment()
        self.addCleanup(h.reset_enrollment)
        pair("--name", "pytest", "--this-parent")
        pair("--name", "victim", "--hash", "22" * 32)
        srv = self.server()
        c = self.legacy_client(srv)
        nh = self.host()
        nm_write(nh, {"type": "client_list"})
        reply = nm_read(nh)
        clients = reply.pop("clients")
        self.assertEqual(reply, {"type": "client_list_result", "ok": True, "enrolled": True})
        self.assertEqual(sorted(cl["name"] for cl in clients), ["pytest", "victim"])
        before = h.read_trust()["epoch"]
        nm_write(nh, {"type": "client_revoke", "name": "victim"})
        self.assertEqual(nm_read(nh), {"type": "client_revoke_result", "ok": True})
        self.assertEqual([cl["name"] for cl in h.read_trust()["clients"]], ["pytest"])
        self.assertGreater(h.read_trust()["epoch"], before)
        self.assertRoundTrip(c, nh, 60)
        nm_write(nh, {"type": "client_revoke", "name": "ghost"})
        self.assertEqual(nm_read(nh), {"type": "client_revoke_result", "ok": False,
                                       "error": "no trusted client named 'ghost'"})

    def test_a19_deleting_the_trust_record_is_the_loud_bootstrap(self):
        """The whole trust state is one record, so deleting it is the documented
        same-user revert to the open bootstrap: no user-space marker survives a
        writer who can delete any file we can write. The revert is ERROR-logged,
        never silent."""
        self.skip_unless_unix("harness attestation")
        h.reset_enrollment()
        self.addCleanup(h.reset_enrollment)
        pair("--name", "pytest", "--this-parent")
        h.reset_enrollment()
        srv = self.server()
        self.assertIn("harness admitted WITHOUT attestation enforcement", h.server_stderr(srv))


class KillSwitch(AdversarialCase):
    def test_a20_kill_reaches_every_enforcement_point(self):
        """With a paired, driving client: the live broker refuses with typed
        BRIDGE_KILLED and keeps the connection, the browser leg is severed, a
        fresh host is control-plane only, and a relay gets the same refusal."""
        srv, c, nh = self.enrolled_broker()
        self.addCleanup(h.run_with_cli_presence, ["unkill"], check=False)
        self.assertRoundTrip(c, nh, 60)
        h.run_cli(["kill"], check=True)
        rev = h.read_trust()
        self.assertEqual((rev["killed"], rev["kill_epoch"]), (True, rev["epoch"]),
                         "the kill landed with its epoch bump in one record")
        self.assertEqual(c.call("tab_list", {}, _id=61), tool_error(61, "BRIDGE_KILLED", h.BRIDGE_KILLED))
        self.assertEqual(c.ping(_id=62), rpc_result(62, {}), "the harness connection carries refusals")
        self.assertExits(nh, 8, "the connected browser host is severed")
        nh2 = self.host(ready=False)
        self.assertEqual(nm_read(nh2), {"type": "kill_status_result", "ok": True, "killed": True},
                         "a fresh host is control-plane only")
        self.assertFalse(nh2.ready.is_set(), "the fresh host never handshakes the bridge")
        c2 = self.legacy_client(self.instance())
        self.assertEqual(c2.call("tab_list", {}, _id=63), tool_error(63, "BRIDGE_KILLED", h.BRIDGE_KILLED),
                         "a relayed harness gets the same typed refusal")

    def test_a21_corrupt_trust_record_fails_everything_closed(self):
        """An unreadable record makes the kill state unknowable: the live broker
        drops its harness, a fresh instance refuses to start, unkill refuses
        (audited as an error with its presence rung), doctor reports it."""
        srv, c, nh = self.enrolled_broker()
        # Drain the fire-and-forget initialized notification before corrupting:
        # the guard runs on every inbound message.
        self.assertEqual(c.ping(_id=69), rpc_result(69, {}))
        with open(h.runtime_file("trust.json"), "w") as f:
            f.write("{ this is not json")
        c.send({"jsonrpc": "2.0", "id": 70, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        self.assertEqual(self.bounded("the call on an unreadable record", srv.stdout.readline, 10), "",
                         "the live broker drops the harness")
        self.assertRefusedToStart(self.server(wait=False))
        unkill = h.run_with_cli_presence(["unkill"], check=False)
        self.assertEqual(unkill.returncode, 1, unkill.stderr)
        self.assertIn("fail open", unkill.stderr)
        errored = [rec for rec in h.audit_records()
                   if rec["event_kind"] == "kill_release" and rec.get("outcome") == "error"]
        self.assertEqual(len(errored), 1, "the errored release attempt is audited once")
        self.assertIn("auth=tty", errored[0]["detail"])
        self.assertIn("write refused", errored[0]["detail"])
        doc = h.run_cli(["doctor"])
        self.assertEqual(doc.returncode, 1, doc.stdout)
        self.assertIn("UNREADABLE", doc.stdout)

    def test_a22_unkill_demands_user_presence(self):
        """Releasing the kill switch needs the presence floor: a piped stdin and
        a wrong phrase are refused and audited with the presence reason; the
        phrase typed on a pty releases, audited with its rung."""
        self.skip_unless_unix("the pty-driven confirmation")
        self.addCleanup(h.run_with_cli_presence, ["unkill"], check=False)
        h.remove_lock()
        already = len(h.audit_records())
        h.run_cli(["kill"], check=True)
        self.assertIs(h.read_trust()["killed"], True)
        piped = h.run_cli(["unkill"], input="release\n")
        self.assertEqual(piped.returncode, 1, piped.stderr)
        self.assertIn("not a terminal", piped.stderr)
        self.assertIs(h.read_trust()["killed"], True, "engaged after the piped attempt")
        wrong = h.run_with_cli_presence(["unkill"], phrase="yes", check=False)
        self.assertEqual(wrong.returncode, 1, wrong.stderr)
        self.assertIs(h.read_trust()["killed"], True, "engaged after the declined prompt")
        ok = h.run_with_cli_presence(["unkill"])
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIs(h.read_trust()["killed"], False)
        releases = [rec for rec in h.audit_records()[already:] if rec["event_kind"] == "kill_release"]
        self.assertEqual([rec["outcome"] for rec in releases], ["refused", "refused", "ok"])
        for rec in releases[:2]:
            self.assertIn("presence", rec["detail"], "the refusal names the presence gate")
        self.assertIn("auth=tty", releases[2]["detail"])


class Versions(AdversarialCase):
    """Stateless 2026-07-28 negotiation abuse. A connection opens with a legacy
    initialize or a well-formed stateless request; anything else is dropped.
    Post-open: an unsupported string version is -32022, malformed or incomplete
    _meta is -32602, and a bare request is served only on an initialize-opened
    connection."""

    JUNK_STRINGS = ["", "1999-01-01", "2026-07-28-rc1"]
    JUNK_NON_STRINGS = [("number", 7), ("boolean", True), ("null", None),
                        ("object", {"v": "2026-07-28"}), ("array", ["2026-07-28"])]

    def test_a23_junk_meta_protocol_version_values(self):
        """Every junk version is a per-request verdict that leaves the
        connection usable; the first one even serves as the opener."""
        srv = self.server()
        c = McpClient(srv)
        # No subTest: every request rides one connection, and a timed-out read
        # leaves a reader that would swallow the next reply.
        for i, bad in enumerate(self.JUNK_STRINGS):
            r = self.bounded(f"reply for {bad!r}", lambda: c.modern_tools_list(_id=100 + i, version=bad), 10)
            self.assertEqual(r, h.unsupported_version(100 + i, bad), f"version {bad!r}")
        for i, (kind, bad) in enumerate(self.JUNK_NON_STRINGS):
            r = self.bounded(f"reply for {kind}", lambda: c.modern_tools_list(_id=110 + i, version=bad), 10)
            self.assertEqual(r, rpc_error(110 + i, -32602, MISSING_META + h.META_VERSION_KEY), f"version as {kind}")
        # The legacy version IN _meta is a legitimate per-request era selection.
        r = self.bounded("legacy version in _meta", lambda: c.modern_tools_list(_id=130, version=h.LEGACY_VERSION), 10)
        self.assertToolsList(r, 130, {})
        c.send({"jsonrpc": "2.0", "id": 140, "method": "tools/list", "params": {"_meta": {}}})
        self.assertEqual(self.bounded("empty _meta", c.recv, 10), rpc_error(140, -32602, MISSING_BOTH))
        self.assertToolsList(self.bounded("positive control", lambda: c.modern_tools_list(_id=150), 10),
                             150, h.TOOLS_LIST_ENVELOPE)
        self.assertEqual(normalized(self.bounded("legacy initialize", c.initialize, 10)),
                         rpc_result(1, h.legacy_init_result()))
        self.assertIsNone(srv.poll(), "the server survived the junk versions")

    def test_a24_bare_discover_opener_and_hostile_flood(self):
        """A bare server/discover as the first request drops the connection (no
        era can be established); 40 rounds of valid discovers interleaved with
        junk versions wedge nothing: every reply keeps its full shape and the
        connection is still modern-opened afterwards."""
        srv = self.server()
        McpClient(srv).send({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        self.assertEqual(h.read_reply_or_eof(srv), "", "the bare opener gets no reply")
        self.assertExits(srv, 5, "the server dropped the connection")

        srv = self.server()
        c = McpClient(srv)
        # No subTest: one connection, so a timed-out read must end the case.
        for i in range(40):
            _id = 200 + 2 * i
            self.assertEqual(normalized(self.bounded(f"discover #{i}", lambda: c.discover(_id=_id), 10)),
                             rpc_result(_id, h.DISCOVER_RESULT), f"round {i}")
            junk = f"1999-01-{(i % 28) + 1:02d}"
            self.assertEqual(self.bounded(f"junk #{i}", lambda: c.modern_tools_list(_id=_id + 1, version=junk), 10),
                             h.unsupported_version(_id + 1, junk), f"round {i}")
        self.assertEqual(self.bounded("bare ping", lambda: c.ping(_id=290), 10),
                         rpc_error(290, -32602, MISSING_BOTH), "no legacy leniency after a modern opener")
        self.assertEqual(self.bounded("modern unknown method", lambda: c.modern_send("no/such_method", _id=291), 10),
                         rpc_error(291, -32601, "no/such_method"))
        self.assertEqual(self.bounded("modern ping", lambda: c.modern_send("ping", _id=292), 10),
                         rpc_error(292, -32601, "ping"), "ping is legacy vocabulary")
        self.assertEqual(normalized(self.bounded("legacy initialize", c.initialize, 10)),
                         rpc_result(1, h.legacy_init_result()))
        self.assertIsNone(srv.poll(), "the server survived the flood")


if __name__ == "__main__":
    unittest.main(verbosity=2)
