"""Fault-injection / chaos suite for genkan's runtime paths.

The e2e suite drives the happy path. Real bugs hide in the other paths: a peer
that vanishes mid-frame, a truncated length prefix at a process boundary, a
storm of reconnects, a server SIGKILLed with a request in flight (a takeover
bug once lived exactly here: the socket unlinked under a freshly bound
listener). Each case injects one fault against the real release binary and
asserts the same invariant: the server stays healthy or fails CLOSED and
RECOVERS, with no hang, no fd or process leak, no corruption, no panic.

  C1   abrupt socket drop with a request in flight   LIVE  caller fails fast, server recovers
  C2   truncated native-messaging frame at the host  LIVE  clean reject, server alive
  C3   reconnect storm (40 hosts)                    LIVE  healthy, no fd leak
  C4   concurrent server starts                      LIVE  one broker + relays, all drive the bridge
  C5   server SIGKILLed mid-request                   LIVE  client EOF, fresh server recovers
  C6   peer death in the connect/handshake window     LIVE  no stale slot, accept loop alive
  C7   stale lock + socket from an ungraceful exit    LIVE  next server rebinds
  C9   relay attach/drop churn                        LIVE  broker ref-count stays healthy
  C10  revoke mid-session                             LIVE  the admission gate drops the harness
  C12  kill mid-dispatch                              LIVE  in-flight call fails fast and typed
  C13  audit sink failure during decisions            LIVE  log-after-decide, gap counted
  C8   MV3 service-worker death mid-op               REF   browser-gated: only a real browser evicts
                                                           a real worker; needs an isolated Chrome
  C11  revoke across a service-worker restart        REF   browser-gated; the socket half is C10
                                                           and adversarial A17/A18

About C1: only this binary passes attestation, so a black-box test cannot
write half a bridge line from a foreign process (that path is unreachable and
covered by the protocol.rs proptests). What C1 injects is the equivalent
fault an attested peer can cause: dropping the connection abruptly while the
server has a request outstanding to it.

About C6: killing a host squarely between the handshake's first and last byte
is inherently racy (a few microseconds on a local socket). C6 proves the
invariant that holds for every interleaving: a peer the server accepted and
then lost, before or after the handshake completed, leaves no stale registry
slot and never wedges the accept loop. It anchors that with a deterministic
sub-case (a foreign peer that connects and vanishes) and a racy one (hosts
killed the instant they report a completed connect).

Every blocking read runs under a hard timeout, so a fault-path regression
surfaces as a failed test, never a hung CI job. Every subprocess runs inside a
private runtime dir (harness.isolate); the drift answer each test pins is its
first docstring line.

Run: `moon run test-chaos` (or `python -m unittest discover -s tests/protocol -p chaos.py -v`).
"""
import os
import struct
import subprocess
import sys
import time
import unittest

import harness as h
from harness import BridgeCase, McpClient, Served, rpc_result, tool_error, tool_result


def setUpModule():
    h.ensure_binary()
    h.isolate("genkan-chaos-")


def tearDownModule():
    h.teardown()


def tab(title):
    return [{"id": 1, "title": title, "url": "https://x", "active": True}]


FORWARDED_TAB_LIST = {"op": "tab_list", "args": {}, "browser": "default"}


def count_fds(pid):
    """Open-descriptor count for `pid` (Linux: /proc; macOS: lsof), or None
    when unmeasurable so the caller fails rather than passes vacuously."""
    if sys.platform.startswith("linux"):
        try:
            return len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            return None
    try:
        out = subprocess.run(["lsof", "-nP", "-p", str(pid)], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
    if lines and lines[0].startswith("COMMAND"):
        lines = lines[1:]
    return len(lines)


def settle_fds(pid, timeout=10):
    """Wait until the fd count is stable across two reads: reader-thread
    cleanup after a disconnect is asynchronous."""
    prev = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        cur = count_fds(pid)
        if cur is not None and cur == prev:
            return
        prev = cur
        time.sleep(0.25)


class ChaosCase(BridgeCase):
    def mcp_ready(self, srv, secs=20):
        """A legacy-initialized client over `srv`, under a timeout."""
        c = McpClient(srv)
        self.bounded("MCP initialize", lambda: (c.initialize(), c.initialized()), secs)
        return c

    def assertRoundTrip(self, c, nh, title, _id, secs=30):
        """One tab_list call through the ready host `nh` returns its data whole."""
        served = Served(nh, tab(title))
        r = self.bounded(f"round-trip {title}", lambda: c.call("tab_list", {}, _id=_id), secs)
        self.assertEqual(served.request(), FORWARDED_TAB_LIST)
        self.assertEqual(r, tool_result(_id, tab(title)))

    def in_flight(self, c, nh, _id):
        """Fire a tool call and confirm the host holds it (the request arrived
        as an NM frame) before the fault is injected."""
        c.send({"jsonrpc": "2.0", "id": _id, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        req = self.bounded("in-flight frame read", lambda: h.nm_read(nh), 15)
        self.assertEqual(h.without_id(req), FORWARDED_TAB_LIST, "the request is in flight at the host")

    def enrolled_broker(self):
        return super().enrolled_broker(self.mcp_ready)


class Faults(ChaosCase):
    def test_c1_abrupt_drop_mid_request(self):
        """A host killed with a request outstanding fails the caller fast and
        typed (not the full response timeout), and a fresh host round-trips on
        the same server."""
        self.skip_unless_unix("the attested-peer drop path")
        srv = self.server()
        c = self.mcp_ready(srv)
        nh = self.host()
        c.send({"jsonrpc": "2.0", "id": 41, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        req = self.bounded("in-flight frame read", lambda: h.nm_read(nh), 15)
        self.assertEqual(h.without_id(req), FORWARDED_TAB_LIST)
        h.kill(nh)
        r = self.bounded("the in-flight call", c.recv, 20)
        self.assertEqual(r, tool_error(41, "CONNECTION_LOST", h.CONNECTION_LOST))
        self.assertIsNone(srv.poll(), "the server survived the abrupt drop")
        self.assertRoundTrip(c, self.host(), "C1 Recovered", 42)

    # (label, the bytes before EOF, the host's exit code, the stderr line it logs)
    TRUNCATED = [
        ("partial length prefix", b"\x02\x00", 0, "stdin EOF"),
        ("truncated body", struct.pack("<I", 4096) + b'{"', 0, "stdin read error"),
    ]

    def test_c2_truncated_nm_frame(self):
        """A short read at a frame boundary is Chrome's canonical EOF (clean
        exit); a body shorter than its prefix is a hard read error. Either
        way the host exits, the server keeps serving, and a fresh host works."""
        self.skip_unless_unix("the native-host leg")
        for i, (label, data, code, logged) in enumerate(self.TRUNCATED):
            with self.subTest(frame=label):
                srv = self.server()
                c = self.mcp_ready(srv)
                nh = self.host()
                nh.stdin.write(data)
                nh.stdin.flush()
                nh.stdin.close()
                self.assertExits(nh, 5, "the host exited (no hang)")
                self.assertEqual(nh.returncode, code, h.host_stderr(nh))
                self.assertIn(logged, h.host_stderr(nh))
                self.assertIsNone(srv.poll(), "the server survived")
                self.assertEqual(self.bounded("ping", lambda: c.ping(_id=201 + i), 15), rpc_result(201 + i, {}))
                self.assertRoundTrip(c, self.host(), f"C2 OK {i}", 203 + i)
            self.doCleanups()

    def test_c3_reconnect_storm(self):
        """40 hosts connecting and dying leave the server healthy with a bounded
        fd count: a leak of one descriptor per reconnect would show as ~40."""
        self.skip_unless_unix("fd inspection")
        srv = self.server()
        c = self.mcp_ready(srv)
        # One warm-up connect so one-time fds are already open: the baseline
        # then isolates per-reconnect growth.
        h.reap(self.host())
        settle_fds(srv.pid)
        baseline = count_fds(srv.pid)
        self.assertIsNotNone(baseline, "the server fd count is measurable")
        storm = 40
        ready = 0
        for _ in range(storm):
            nh = h.start_bridge_host()
            if nh.ready.wait(10):
                ready += 1
            h.kill(nh)
            h.reap(nh)
        self.assertGreaterEqual(ready, int(storm * 0.9), "the storm really reconnected")
        settle_fds(srv.pid)
        final = count_fds(srv.pid)
        self.assertIsNotNone(final)
        self.assertLessEqual(final, baseline + 12, f"fds bounded (baseline {baseline}, after {ready} reconnects {final})")
        self.assertIsNone(srv.poll(), "the server survived the storm")
        self.assertRoundTrip(c, self.host(), "C3 OK", 301)

    def test_c5_server_killed_mid_request(self):
        """SIGKILLing the server with a request in flight gives the client a
        clean EOF, never a corrupt response, and a fresh server starts over the
        crash's leftovers."""
        self.skip_unless_unix("the native-host round-trip")
        srv = self.server()
        c = self.mcp_ready(srv)
        nh = self.host()
        self.in_flight(c, nh, 51)
        h.kill(srv)
        self.assertEqual(h.read_reply_or_eof(srv, 15), "", "a clean EOF, never a corrupt response")
        srv2 = self.server(clear_lock=False)
        self.assertRoundTrip(self.mcp_ready(srv2), self.host(), "C5 Recovered", 52)

    def test_c6_peer_death_in_the_handshake_window(self):
        """Peers lost after accept (foreign ones rejected at attestation, real
        hosts killed inside the attestation+handshake window) leave no stale
        browser slot and do not wedge the accept loop."""
        self.skip_unless_unix("attestation and the handshake window")
        srv = self.server()
        c = self.mcp_ready(srv)
        for _ in range(10):
            h.foreign_peer_outcome(srv.lock)
        deadline = time.time() + 5
        while "rejected bridge connection" not in h.server_stderr(srv) and time.time() < deadline:
            time.sleep(0.1)
        self.assertIn("rejected bridge connection", h.server_stderr(srv))
        self.assertIsNone(srv.poll(), "the accept loop survived the vanishing foreign peers")
        reached = 0
        for _ in range(8):
            nh = h.start_bridge_host()
            if nh.connected.wait(8):
                reached += 1
            h.kill(nh)
            h.reap(nh)
        self.assertGreaterEqual(reached, 6, "hosts reached the connect/handshake window")
        self.assertIsNone(srv.poll(), "the server survived the in-window deaths")
        self.assertEventually(
            lambda: h.browsers_listing(self.bounded("list_browsers", lambda: c.call("list_browsers", {}, _id=601), 15)),
            {"browsers": [], "count": 0}, 8, "no stale browser slot")
        self.assertRoundTrip(c, self.host(), "C6 OK", 602)

    def test_c7_stale_lock_and_socket(self):
        """A SIGKILLed server leaves its lock and socket behind; the next server
        cleans them up, binds fresh, and actually serves."""
        self.skip_unless_unix("the filesystem socket")
        srv = self.server()
        self.assertTrue(os.path.exists(h.socket_path()), "the socket exists on disk")
        h.kill(srv)
        self.assertEqual((os.path.exists(h.LOCK), os.path.exists(h.socket_path())), (True, True),
                         "lock and socket left stale after SIGKILL")
        srv2 = self.server(clear_lock=False)
        self.assertTrue(os.path.exists(h.socket_path()), "the next server's socket exists")
        self.assertRoundTrip(self.mcp_ready(srv2), self.host(), "C7 OK", 701)


class Coexistence(ChaosCase):
    def test_c4_concurrent_servers_coexist(self):
        """Six instances starting at once, three rounds: all stay alive, exactly
        one owns the lock, and a RELAY's tool call round-trips through the
        broker's socket (the multiplex path is live under concurrent startup)."""
        for rnd in range(1, 4):
            with self.subTest(round=rnd):
                h.remove_lock()
                servers = [self.instance() for _ in range(6)]
                deadline = time.time() + 20
                lf = None
                while time.time() < deadline:
                    lf = h.wait_lock(timeout=1)
                    if lf is not None and all(s.poll() is None for s in servers):
                        break
                    time.sleep(0.2)
                self.assertEqual([s.poll() for s in servers], [None] * 6, "all instances coexist")
                locks = [h.lock_published_by(s) for s in servers]
                self.assertIn(h.lock_record(lf), locks, "the lock names one of the instances")
                if os.name != "nt":
                    self.assertTrue(os.path.exists(h.socket_path()), "the broker's socket exists")
                relay = next(s for s in servers if h.lock_published_by(s) != h.lock_record(lf))
                self.assertRoundTrip(self.mcp_ready(relay), self.host(), "C4 Coexist", 400 + rnd)
            self.doCleanups()

    def test_c9_relay_attach_drop_churn(self):
        """Batches of relays attached and SIGKILLed never underflow or wedge the
        broker's ref-count: it keeps the lock and keeps driving the browser,
        then exits once its own harness detaches."""
        self.skip_unless_unix("broker/relay coexistence")
        broker = self.server()
        cb = self.mcp_ready(broker)
        nh = self.host()
        # No subTest: the cycles share one broker and host, and a timed-out
        # round trip leaves a reader on the host that would desync the next.
        for cycle in range(4):
            batch = [self.instance() for _ in range(3)]
            time.sleep(0.6)
            self.assertEqual([s.poll() for s in batch], [None] * 3, f"cycle {cycle}: relays attached and coexist")
            self.assertIsNone(broker.poll(), f"cycle {cycle}: the broker survives the attach")
            for s in batch:
                h.kill(s)
            time.sleep(0.4)
            self.assertIsNone(broker.poll(), f"cycle {cycle}: the broker survives the abrupt relay drop")
            self.assertLock(h.wait_lock(broker, timeout=2), broker, f"cycle {cycle}: the broker still owns the lock")
            self.assertRoundTrip(cb, nh, f"C9-{cycle}", 900 + cycle)
        broker.stdin.close()
        self.assertExits(broker, 10, "the broker exits once its last harness detaches")
        self.assertFalse(os.path.exists(h.LOCK), "the broker removed its lock on final exit")


class Enforcement(ChaosCase):
    def test_c10_revoke_mid_dispatch(self):
        """A revoke mid-session drops the harness at the per-request admission gate
        (EOF, broker exits), and a re-paired client gets a fresh, serving
        broker: no wedged socket owner is left behind."""
        broker, cb, nh = self.enrolled_broker()
        self.assertRoundTrip(cb, nh, "C10-before", 1000)
        h.run_cli(["revoke-client", "--name", "pytest"], check=True)
        cb.send({"jsonrpc": "2.0", "id": 1001, "method": "tools/call",
                 "params": {"name": "tab_list", "arguments": {}}})
        self.assertEqual(self.bounded("the revoked call", broker.stdout.readline, 10), "",
                         "the revoked harness gets EOF")
        self.assertExits(broker, 8, "the broker for the revoked harness exits")
        h.pair_client("pytest", "--this-parent")
        broker2 = self.server()
        self.assertRoundTrip(self.mcp_ready(broker2), self.host(), "C10-after", 1002)

    def test_c12_kill_mid_dispatch(self):
        """Engaging the kill switch with a call in flight fails that caller fast
        and typed (the severed leg, not a 120 s timeout), refuses the next call
        with BRIDGE_KILLED, and a release restores the same broker."""
        broker, cb, nh = self.enrolled_broker()
        self.addCleanup(h.run_with_cli_presence, ["unkill"], check=False)
        self.assertRoundTrip(cb, nh, "C12-before", 1100)
        self.in_flight(cb, nh, 1101)
        h.run_cli(["kill"], check=True)
        self.assertEqual(self.bounded("the in-flight call", cb.recv, 15),
                         tool_error(1101, "CONNECTION_LOST", h.CONNECTION_LOST))
        self.assertEqual(self.bounded("the next call", lambda: cb.call("tab_list", {}, _id=1102), 10),
                         tool_error(1102, "BRIDGE_KILLED", h.BRIDGE_KILLED))
        h.run_with_cli_presence(["unkill"])
        self.assertRoundTrip(cb, self.host(), "C12-after", 1103)

    def test_c13_audit_sink_failure_never_fails_the_decision(self):
        """With the audit file replaced by a directory every append fails, yet
        tool calls flow, a kill engages, refuses typed, and severs the browser
        leg; once the sink heals the trail resumes, and the broker's first
        record carries a dropped counter for its gap."""
        attached = len(h.audit_records(("browser_attach",)))
        broker, cb, nh = self.enrolled_broker()
        # The broker records the attach after it has told the host it is
        # accepted, so the host's readiness does not put the record on disk.
        self.assertEventually(lambda: h.audit_records(("browser_attach",))[attached:],
                              [h.audit_record("browser_attach", surface="broker", outcome="ok", name="default")],
                              5, "the host's attach is in the trail before the sink breaks")
        self.addCleanup(h.run_with_cli_presence, ["unkill"], check=False)
        audit_path = h.runtime_file("audit.log")
        self.addCleanup(self._rmdir, audit_path)
        try:
            os.remove(audit_path)
        except FileNotFoundError:
            pass
        os.mkdir(audit_path)
        self.assertRoundTrip(cb, nh, "C13-broken-sink", 1200)
        kill = h.run_cli(["kill"])
        self.assertEqual(kill.returncode, 0, kill.stderr)
        self.assertEqual(cb.call("tab_list", {}, _id=1201), tool_error(1201, "BRIDGE_KILLED", h.BRIDGE_KILLED))
        self.assertExits(nh, 8, "the kill severs the browser leg with the sink broken")
        h.run_with_cli_presence(["unkill"])
        os.rmdir(audit_path)
        h.run_cli(["kill"], check=True)
        h.run_with_cli_presence(["unkill"])
        self.assertRoundTrip(cb, self.host(), "C13-healed", 1202)
        self.assertEqual(h.audit_records(), [
            h.audit_record("kill_engage", surface="cli", outcome="ok"),
            h.audit_record("kill_release", surface="cli", outcome="ok", detail="auth=tty"),
            h.audit_record("browser_attach", surface="broker", outcome="ok", name="default", dropped=2),
            h.tool_call_record(req=3, outcome="ok", name="default", conn=2),
        ], "the post-heal trail: the CLI's decisions, then the broker's two failed appends counted")

    @staticmethod
    def _rmdir(path):
        try:
            os.rmdir(path)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
