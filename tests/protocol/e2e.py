"""End-to-end protocol tests for chromium-bridge.

Each case drives the release binary as real subprocesses: the MCP server over
JSON-RPC/stdio, `--native-host` over Chrome Native-Messaging frames, and tool
round-trips that flow client -> server -> attested host -> "extension" (this
suite, answering frames) and back. Only the binary itself passes the broker's
peer attestation, so the extension leg always rides a real `--native-host`
subprocess; `Broker.test_foreign_peer_is_refused_by_attestation` pins that a
raw socket peer is dropped.

The MCP layer is pinned in both eras: 2026-07-28 stateless requests (per-request
_meta version + capabilities) and the temporary legacy era for bare requests on
initialize-opened connections (`LegacyShim`, deleted with that era).

Run: `moon run test-e2e` (or `python -m unittest discover -s tests/protocol -p e2e.py -v`).
Every server runs in a private runtime dir (harness.isolate); the drift answer
each test pins is its first docstring line.
"""
import json
import os
import subprocess
import time
import unittest

import harness as h
from harness import (BridgeCase, McpClient, Served, nm_read, nm_read_raw, nm_read_type,
                     nm_write, normalized, rpc_error, rpc_result, tool_error, tool_result)


def setUpModule():
    h.ensure_binary()
    h.isolate("bb-e2e-")


# The user-facing warnings a tool description must keep carrying.
DESCRIPTION_WARNINGS = [
    ("page_eval", "HIGH RISK"),
    ("page_snapshot_precise", "debugger"),
    ("cookie_get", "httpOnly"),
    ("cookie_get", "masked"),
]
MISSING_META = "request _meta is missing or has malformed required fields: "
NOT_CONNECTED = "browser extension not connected - is the extension loaded and Chrome running?"


def tabs(title, _id=7):
    return [{"id": _id, "title": title, "url": "https://x", "active": True}]


def forwarded(op, args=None, browser="default"):
    """The BridgeReq envelope the server forwards to the host for one call
    (its correlation id stripped by Served.request)."""
    return {"op": op, "args": args or {}, "browser": browser}


class E2ECase(BridgeCase):
    def assertRoundTrip(self, c, nh, _id, title, args=None, modern=False):
        """One legacy (or modern) tab_list call flows through `nh` and brings
        its data back whole."""
        served = Served(nh, tabs(title))
        r = c.modern_call("tab_list", args or {}, _id=_id) if modern else c.call("tab_list", args or {}, _id=_id)
        self.assertEqual(served.request(), forwarded("tab_list", args, browser=(args or {}).get("browser", "default")))
        self.assertEqual(r, tool_result(_id, tabs(title), modern=modern))


class ModernEra(E2ECase):
    def test_discover_and_the_tool_catalogue(self):
        """The discover result and the full catalogue (every name, description,
        and schema) are the contract a stateless client reads; a tool's risk
        warning is the user's only notice."""
        c = McpClient(self.server())
        self.assertEqual(normalized(c.discover(_id=1)), rpc_result(1, h.DISCOVER_RESULT))
        tools = self.assertToolsList(c.modern_tools_list(_id=2), 2, h.TOOLS_LIST_ENVELOPE)
        # Checked on the served reply, so a hand re-pin of the literal that
        # drops a warning still fails here.
        by_name = {t["name"]: t for t in tools}
        for name, needle in DESCRIPTION_WARNINGS:
            with self.subTest(tool=name, warning=needle):
                self.assertIn(needle.lower(), by_name[name]["description"].lower())

    def test_discover_is_served_as_the_first_request(self):
        """server/discover with its own _meta needs no prior traffic; the bare
        probe has no served form and a modern notification gets no reply."""
        c = McpClient(self.server())
        self.assertEqual(normalized(c.discover(_id=1)), rpc_result(1, h.DISCOVER_RESULT))
        self.assertEqual(c.discover(_id=2, meta=False),
                         rpc_error(2, -32602, MISSING_META + f"{h.META_VERSION_KEY}, {h.META_CAPS_KEY}"))
        c.send({"jsonrpc": "2.0", "method": "notifications/initialized",
                "params": c.modern_params()})
        self.assertEqual(normalized(c.discover(_id=3)), rpc_result(3, h.DISCOVER_RESULT))

    OPENERS = [
        ("bare server/discover", {"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
        ("bare tools/list", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ("_meta missing clientCapabilities",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/list",
          "params": {"_meta": {h.META_VERSION_KEY: h.MODERN_VERSION}}}),
    ]

    def test_invalid_opener_drops_the_connection(self):
        """A first request that is neither a legacy initialize nor a well-formed
        stateless request gets no reply and the server exits: a peer whose era
        cannot be established is never served. A bare ping is answered pre-open
        but does not open the connection."""
        for label, first in self.OPENERS:
            with self.subTest(opener=label):
                mcp = self.server()
                McpClient(mcp).send(first)
                self.assertEqual(h.read_reply_or_eof(mcp), "", "no reply, EOF")
                self.assertExits(mcp, 5, "the server closed the connection")
        mcp = self.server()
        c = McpClient(mcp)
        self.assertEqual(c.ping(_id=1), rpc_result(1, {}))
        c.send({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})
        self.assertEqual(h.read_reply_or_eof(mcp), "", "ping did not open the connection")

    def test_tool_order_survives_a_server_restart(self):
        """A catalogue in hash order would list differently per process; the
        served order is the same across calls and across a restart."""
        c = McpClient(self.server())
        self.assertToolsList(c.modern_tools_list(_id=1), 1, h.TOOLS_LIST_ENVELOPE)
        self.assertToolsList(c.modern_tools_list(_id=2), 2, h.TOOLS_LIST_ENVELOPE)
        h.reap(c.proc)
        self.assertToolsList(McpClient(self.server()).modern_tools_list(_id=3), 3, h.TOOLS_LIST_ENVELOPE)

    def test_version_mismatch_is_per_request(self):
        """A wrong string version is -32022 with the supported set, a non-string
        one is -32602 naming the field, and the same connection serves the next
        correct request."""
        c = McpClient(self.server())
        self.assertEqual(c.modern_tools_list(_id=51, version="2099-01-01"),
                         h.unsupported_version(51, "2099-01-01"))
        self.assertEqual(c.modern_tools_list(_id=52, version=42),
                         rpc_error(52, -32602, MISSING_META + h.META_VERSION_KEY))
        self.assertEqual(c.discover(_id=53, version="2099-01-01"),
                         h.unsupported_version(53, "2099-01-01"))
        self.assertToolsList(c.modern_tools_list(_id=54), 54, h.TOOLS_LIST_ENVELOPE)

    def test_initialize_is_served_in_every_era(self):
        """rmcp answers initialize as the legacy negotiation whatever the _meta:
        a modern or unknown requested revision gets the newest legacy one."""
        c = McpClient(self.server())
        r = c.modern_send("initialize", {"protocolVersion": h.MODERN_VERSION, "capabilities": {},
                                         "clientInfo": {"name": "e2e", "version": "0.1"}}, _id=61)
        self.assertEqual(normalized(r), rpc_result(61, h.legacy_init_result(h.NEWEST_LEGACY_VERSION)))
        self.assertEqual(normalized(c.initialize(version="1999-01-01", _id=62)),
                         rpc_result(62, h.legacy_init_result(h.NEWEST_LEGACY_VERSION)))

    def test_tools_call_round_trip(self):
        """A modern tools/call is the connection's first request (no handshake)
        and returns the host's data in the stateless result shape."""
        mcp = self.server()
        nh = self.host()
        self.assertRoundTrip(McpClient(mcp), nh, 5, "Modern E2E Tab", modern=True)

    def test_unknown_method_in_both_eras(self):
        """An unknown method is JSON-RPC -32601 in the legacy and the modern era."""
        c = self.legacy_client(self.server())
        c.send({"jsonrpc": "2.0", "id": 11, "method": "resources/list"})
        self.assertEqual(c.recv(), rpc_error(11, -32601, "resources/list"))
        self.assertEqual(c.modern_send("resources/list", _id=12), rpc_error(12, -32601, "resources/list"))


class LegacyShim(E2ECase):
    """Bare requests on an initialize-opened connection keep the pre-migration
    shapes byte-identical until that era is removed."""

    def test_handshake_keeps_the_legacy_shapes(self):
        """initialize answers 2025-06-18 with none of the modern keys, the
        initialized notification is swallowed, and ping returns exactly {}."""
        c = McpClient(self.server())
        self.assertEqual(normalized(c.initialize()), rpc_result(1, h.legacy_init_result()))
        c.initialized()
        self.assertEqual(c.ping(_id=5), rpc_result(5, {}))

    def test_tools_list_has_no_modern_fields(self):
        """The era discriminator is the _meta version KEY: a bare tools/list and
        one whose _meta has only a progressToken both get the bare result."""
        c = self.legacy_client(self.server())
        self.assertToolsList(c.tools_list(_id=6), 6, {})
        c.send({"jsonrpc": "2.0", "id": 7, "method": "tools/list",
                "params": {"_meta": {"io.modelcontextprotocol/progressToken": "t1"}}})
        self.assertToolsList(c.recv(), 7, {})

    def test_mixed_era_interleaving(self):
        """The era is a per-request property, never connection state: one
        connection serves both eras request by request, each in its own shape."""
        c = McpClient(self.server())
        self.assertEqual(normalized(c.initialize()), rpc_result(1, h.legacy_init_result()))
        self.assertEqual(normalized(c.discover(_id=42)), rpc_result(42, h.DISCOVER_RESULT))
        self.assertEqual(c.ping(_id=43), rpc_result(43, {}))
        self.assertToolsList(c.modern_tools_list(_id=44), 44, h.TOOLS_LIST_ENVELOPE)
        self.assertToolsList(c.tools_list(_id=45), 45, {})


class RoundTrips(E2ECase):
    # (tool, arguments, the data the extension answers): one axis of the same flow.
    CASES = [
        ("tab_list", {}, tabs("E2E Tab")),
        ("page_eval", {"code": "return 1 + 41"}, {"result": 42, "masked": "••••[jwt]"}),
        ("page_snapshot_precise", {}, {
            "refCount": 2,
            "nodes": [{"ref": "p1", "role": "textbox", "name": "Search", "selector": "input#q", "value": ""},
                      {"ref": "p2", "role": "button", "name": "Submit", "selector": "button#go", "value": None}],
            "url": "https://example.com", "title": "Example", "precise": True,
        }),
        ("cookie_get", {"url": "https://example.com"}, {
            "cookies": [{"name": "session", "value": "••••[jwt]", "domain": ".example.com",
                         "path": "/", "httpOnly": True, "secure": True, "sameSite": "lax", "session": False}],
            "count": 1,
        }),
        ("storage_get", {"type": "local", "key": "auth_token"},
         {"key": "auth_token", "found": True, "value": "••••[jwt]"}),
    ]

    def test_tool_calls_reach_the_extension_and_return_its_data(self):
        """Each tool's op and arguments arrive at the extension as one NM frame
        and its answer travels back to the client unchanged, masking included."""
        for i, (tool, args, data) in enumerate(self.CASES):
            with self.subTest(tool=tool):
                # Own server and host per case: a timed-out case must not
                # leave a reader on a host the next case reuses.
                c = self.legacy_client(self.server())
                nh = self.host()
                served = Served(nh, data)
                r = c.call(tool, args, _id=10 + i)
                self.assertEqual(served.request(), forwarded(tool, args))
                self.assertEqual(r, tool_result(10 + i, data))


class ControlFrames(E2ECase):
    INVALID_CHALLENGES = [
        ("NUL in the nonce", {"type": "enclave_challenge", "nonce": "bad\x00nonce"}),
        ("missing nonce", {"type": "enclave_challenge"}),
    ]

    def test_enclave_frames_are_answered_locally_not_forwarded(self):
        """The host answers enclave control frames itself (before any keychain
        access, so no Touch ID prompt) and drops a stray proof; ordinary frames
        still flow afterwards, so nothing desynchronized the bridge."""
        mcp = self.server()
        nh = self.host()
        for label, frame in self.INVALID_CHALLENGES:
            with self.subTest(challenge=label):
                nm_write(nh, frame)
                self.assertEqual(nm_read(nh), {"type": "enclave_error", "reason": "invalid_challenge"})
        nm_write(nh, {"type": "enclave_proof", "sig": "x", "key_id": "y", "pubkey": "z"})
        self.assertRoundTrip(self.legacy_client(mcp), nh, 31, "After Control")

    def test_admin_frames_are_answered_locally(self):
        """client_list and client_revoke are answered by the host from the
        trusted-client store, never forwarded; a stray result frame is dropped."""
        self.skip_if_enrolled()
        self.skip_unless_unix("the pty-driven pairing")
        env = self.private_runtime("bb-e2e-admin-")
        h.run_with_cli_presence(["pair-client", "--name", "pytest", "--this-parent"], env=env)
        h.run_with_cli_presence(["pair-client", "--name", "codex", "--hash", "aa" * 32], env=env)
        mcp = self.server(env=env)
        nh = self.host(env=env)
        nm_write(nh, {"type": "client_list"})
        reply = nm_read(nh)
        clients = sorted(reply.pop("clients"), key=lambda cl: cl["name"])
        self.assertEqual(reply, {"type": "client_list_result", "ok": True, "enrolled": True})
        self.assertEqual([cl["name"] for cl in clients], ["codex", "pytest"])
        self.assertEqual({k: v for k, v in clients[0].items() if k != "added_unix"},
                         {"name": "codex", "anchor": {"kind": "hash", "value": "aa" * 32}})
        nm_write(nh, {"type": "client_revoke", "name": "codex"})
        self.assertEqual(nm_read(nh), {"type": "client_revoke_result", "ok": True})
        nm_write(nh, {"type": "client_list_result", "ok": True, "enrolled": True, "clients": []})
        self.assertRoundTrip(self.legacy_client(mcp), nh, 71, "After Admin")

    def test_policy_and_language_frames(self):
        """The host identifies itself unsolicited at connect (policy_current
        then lang_current), answers policy_get/lang_get/lang_set, and drops
        host-direction pushes injected from the browser leg."""
        env = self.private_runtime("bb-e2e-policy-")
        mcp = self.server(env=env)
        nh = self.host(env=env)
        absent = {"type": "policy_current", "ok": False, "error": "no policy baseline on this host"}
        self.assertEqual(nm_read_raw(nh), absent)
        self.assertEqual(nm_read_raw(nh), {"type": "lang_current", "value": "en", "seq": 0})
        c = self.legacy_client(mcp)
        nm_write(nh, {"type": "policy_get"})
        self.assertEqual(nm_read_type(nh, "policy_current"), absent)
        nm_write(nh, {"type": "lang_set", "value": "zh_CN"})
        self.assertEqual(nm_read_type(nh, "lang_current"), {"type": "lang_current", "value": "zh_CN", "seq": 1})
        nm_write(nh, {"type": "lang_get"})
        self.assertEqual(nm_read_type(nh, "lang_current"), {"type": "lang_current", "value": "zh_CN", "seq": 1})
        nm_write(nh, {"type": "policy_current", "ok": True, "baseline": "YmFzZQ==", "sig": "c2ln"})
        nm_write(nh, {"type": "lang_current", "value": "en", "seq": 99})
        self.assertRoundTrip(c, nh, 92, "After Injected")


class KillSwitch(E2ECase):
    def test_kill_engage_refuse_release_recover(self):
        """`kill` halts the live broker with typed BRIDGE_KILLED refusals,
        severs the browser leg, keeps a fresh host control-plane only, refuses
        the extension's retired release frame; `unkill` restores everything,
        and the 0600 audit trail records each step with its surface."""
        self.skip_if_enrolled()
        self.skip_unless_unix("the pty-driven release")
        for name in ("trust.json", "audit.log", "audit.log.1", "audit.log.lock"):
            self.addCleanup(self._remove, h.runtime_file(name))
        already = len(h.audit_records())
        mcp = self.server()
        c = self.legacy_client(mcp)
        nh = self.host()
        self.assertRoundTrip(c, nh, 80, "Before Kill")

        kill = subprocess.run([h.BIN, "kill"], capture_output=True, text=True)
        self.assertEqual(kill.returncode, 0, kill.stderr)
        self.assertEqual(c.call("tab_list", {}, _id=81),
                         tool_error(81, "BRIDGE_KILLED", h.BRIDGE_KILLED))
        self.assertExits(nh, 8, "the connected native host exits after the kill")

        nh2 = self.host(ready=False)
        killed = {"type": "kill_status_result", "ok": True, "killed": True}
        self.assertEqual(nm_read(nh2), killed, "a fresh host announces the killed state")
        self.assertFalse(nh2.ready.is_set(), "the control-plane host never handshakes")
        nm_write(nh2, {"type": "kill_status"})
        self.assertEqual(nm_read(nh2), killed)
        nm_write(nh2, {"type": "kill_release"})
        refused = nm_read(nh2)
        self.assertIn("kill_release from the extension is retired", refused.pop("error"))
        self.assertEqual(refused, {"type": "kill_status_result", "ok": False},
                         "the extension release is refused with no killed claim")
        nm_write(nh2, {"type": "kill_status"})
        self.assertEqual(nm_read(nh2), killed, "the refused release left the switch engaged")

        h.run_with_cli_presence(["unkill"])
        self.bounded("drain the control-plane host", lambda: list(iter(lambda: nm_read(nh2), None)), 8)
        self.assertExits(nh2, 8, "the control-plane host exits after the release")
        self.assertRoundTrip(c, self.host(), 82, "Recovered")

        audit_path = h.runtime_file("audit.log")
        if os.name != "nt":
            self.assertEqual(os.stat(audit_path).st_mode & 0o777, 0o600)
        # This test's own decisions, in order (attach/admit records interleave
        # and belong to other invariants).
        trail = [(rec["event_kind"], rec.get("surface"), rec.get("outcome"), rec.get("code"))
                 for rec in h.audit_records()[already:]
                 if rec["event_kind"] in ("tool_call", "kill_engage", "kill_release")]
        self.assertEqual(trail, [
            ("tool_call", None, "ok", None),
            ("kill_engage", "cli", "ok", None),
            ("tool_call", None, "error", "BRIDGE_KILLED"),
            ("kill_release", "extension", "refused", None),
            ("kill_release", "cli", "ok", None),
            ("tool_call", None, "ok", None),
        ])
        cli_release = next(rec for rec in h.audit_records()
                           if rec.get("event_kind") == "kill_release" and rec.get("surface") == "cli")
        self.assertIn("auth=cli_confirm", cli_release["detail"], "the release names its presence rung")
        shown = subprocess.run([h.BIN, "audit"], capture_output=True, text=True)
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertIn("kill_engage", shown.stdout)
        self.assertIn("kill_release", shown.stdout)

    @staticmethod
    def _remove(path):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


class Isolation(unittest.TestCase):
    def test_windows_children_are_isolated_through_localappdata(self):
        """lockfile.rs reads LOCALAPPDATA on Windows and ignores XDG_RUNTIME_DIR,
        so a child pointed only at XDG there would run against the real
        per-user dir; the spawn guard must judge the variable the binary reads."""
        rundir = h.new_runtime_dir("bb-e2e-nt-")
        env = h.runtime_env(rundir, platform="nt")
        self.assertEqual(env["LOCALAPPDATA"], rundir)
        saved = h.LOCK
        h.LOCK = h.lock_path(rundir)
        try:
            h.require_isolated(env, platform="nt")
            with self.assertRaises(RuntimeError):
                h.require_isolated({"XDG_RUNTIME_DIR": rundir}, platform="nt")
        finally:
            h.LOCK = saved


class Broker(E2ECase):
    def test_stale_lock_is_replaced(self):
        """A lock left by a dead pid must not block the next server."""
        os.makedirs(os.path.dirname(h.LOCK), exist_ok=True)
        with open(h.LOCK, "w", encoding="utf-8") as f:
            json.dump({"endpoint": "/nonexistent/chromium-bridge/run.sock",
                       "secret": "0" * 32, "pid": 4294967295}, f)
        mcp = h.start_server()
        self.addCleanup(h.reap, mcp)
        lock = h.wait_lock(mcp)
        self.assertEqual(lock and lock["pid"], mcp.pid, "the server replaced the dead pid's lock")

    def test_foreign_peer_is_refused_by_attestation(self):
        """A non-binary peer on the bridge socket is dropped before any
        challenge, and the server logs the executable-identity mismatch."""
        self.skip_unless_unix("executable attestation")
        mcp = self.server()
        self.assertEqual(h.foreign_peer_outcome(mcp.lock), b"", "dropped without a challenge")
        h.reap(mcp)
        self.assertIn("identity mismatch", h.server_stderr(mcp))

    def test_second_instance_coexists_as_relay(self):
        """A second instance does not take over: the first keeps the lock as
        broker, the second attaches as a relay, and both serve their stdio."""
        first = self.server()
        second = self.instance()
        time.sleep(1.0)
        self.assertEqual((first.poll(), second.poll()), (None, None), "both stay alive")
        still = h.wait_lock(first, timeout=2)
        self.assertEqual(still and still["pid"], first.pid, "the lock still names the broker")
        self.assertEqual(normalized(McpClient(first).initialize()), rpc_result(1, h.legacy_init_result()))
        cr = McpClient(second)
        self.assertEqual(normalized(cr.initialize()), rpc_result(1, h.legacy_init_result()))
        self.assertEqual(cr.ping(_id=77), rpc_result(77, {}))

    def test_two_harnesses_drive_one_browser(self):
        """A broker and a relay attached to one browser both route through the
        shared session to the single host."""
        first = self.server()
        second = self.instance()
        time.sleep(1.0)
        self.assertIsNone(second.poll(), "relay attached")
        nh = self.host()
        box = h.serve_bridge_loop(nh, lambda req: {"id": req["id"], "ok": True, "data": tabs("Shared", 1)})
        cb = self.legacy_client(first)
        cr = self.legacy_client(second)
        self.assertEqual(cb.call("tab_list", {}, _id=21), tool_result(21, tabs("Shared", 1)))
        self.assertEqual(cr.call("tab_list", {}, _id=22), tool_result(22, tabs("Shared", 1)))
        self.assertIsNone(box["error"])

    def test_broker_is_ref_counted(self):
        """The broker exits when the last harness detaches and outlives its own
        harness while a relay is attached: no idle daemon, no premature exit."""
        solo = self.server()
        solo.stdin.close()
        self.assertExits(solo, 8, "a lone broker exits when its only harness detaches")
        self.assertFalse(os.path.exists(h.LOCK), "the lone broker removed its lock")

        first = self.server()
        second = self.instance()
        time.sleep(1.0)
        self.assertIsNone(second.poll(), "relay attached")
        first.stdin.close()
        time.sleep(1.0)
        self.assertIsNone(first.poll(), "the broker outlives its own harness")
        still = h.wait_lock(first, timeout=2)
        self.assertEqual(still and still["pid"], first.pid)
        self.assertEqual(McpClient(second).ping(_id=88), rpc_result(88, {}))
        second.stdin.close()
        self.assertExits(first, 10, "the broker exits once the last harness detaches")
        self.assertFalse(os.path.exists(h.LOCK), "the broker removed its lock on final exit")

    def test_concurrent_starts_coexist_and_all_drive_the_bridge(self):
        """Several instances starting at once settle to one lock owner plus
        relays, all alive, each able to drive the one attached browser."""
        h.remove_lock()
        servers = [self.instance() for _ in range(3)]
        deadline = time.time() + 15
        lf = None
        while time.time() < deadline:
            lf = h.wait_lock(timeout=1)
            if lf is not None and all(s.poll() is None for s in servers):
                break
            time.sleep(0.2)
        self.assertEqual([s.poll() for s in servers], [None] * 3, "all instances coexist")
        self.assertIn(lf and lf["pid"], [s.pid for s in servers], "the lock names one instance")
        nh = self.host()
        box = h.serve_bridge_loop(nh, lambda req: {"id": req["id"], "ok": True, "data": tabs("Coexist", 3)})
        for i, s in enumerate(servers):
            with self.subTest(instance=i):
                self.assertEqual(self.legacy_client(s).call("tab_list", {}, _id=30 + i),
                                 tool_result(30 + i, tabs("Coexist", 3)))
        self.assertIsNone(box["error"])


class Browsers(E2ECase):
    def test_two_labeled_browsers_route_independently(self):
        """Two labeled hosts authenticate independently, list_browsers counts
        both, explicit routing reaches each, an unaddressed call is refused
        rather than guessed, and routing collapses when one departs."""
        mcp = self.server()
        c = self.legacy_client(mcp)
        chrome = self.host("chrome")
        brave = self.host("brave")
        if os.name != "nt":
            self.assertEqual(h.foreign_peer_outcome(mcp.lock), b"",
                             "a foreign peer is still refused with two browsers live")

        def responder_for(data, seen):
            def responder(req):
                seen.append(h.without_id(req))
                return {"id": req["id"], "ok": True, "data": data}
            return responder

        chrome_tabs = [{"id": 1, "title": "Chrome Tab", "url": "https://a", "active": True},
                       {"id": 2, "title": "Chrome Tab 2", "url": "https://b", "active": False}]
        brave_tabs = [{"id": 9, "title": "Brave Tab", "url": "https://c", "active": True}]
        chrome_seen, brave_seen = [], []
        chrome_box = h.serve_bridge_loop(chrome, responder_for(chrome_tabs, chrome_seen))
        brave_box = h.serve_bridge_loop(brave, responder_for(brave_tabs, brave_seen))

        listing = h.tool_payload(c.call("list_browsers", {}, _id=20))
        listing["browsers"].sort(key=lambda b: b["label"])
        self.assertEqual(listing, {"browsers": [{"label": "brave", "tabCount": 1},
                                                {"label": "chrome", "tabCount": 2}], "count": 2})
        self.assertEqual(c.call("tab_list", {"browser": "chrome"}, _id=21), tool_result(21, chrome_tabs))
        self.assertEqual(c.call("tab_list", {"browser": "brave"}, _id=22), tool_result(22, brave_tabs))
        self.assertEqual(c.call("tab_list", {}, _id=23),
                         tool_error(23, "BROWSER_AMBIGUOUS", h.browser_ambiguous(["brave", "chrome"])))
        self.assertEqual(c.call("tab_list", {"browser": "edge"}, _id=24),
                         tool_error(24, "BROWSER_NOT_FOUND", h.browser_not_found("edge", ["brave", "chrome"])))
        n_served = len(chrome_seen) + len(brave_seen)
        self.assertEqual(c.call("tab_list", {"browser": 123}, _id=28),
                         tool_error(28, "INVALID_ARGUMENT",
                                    "invalid `browser` argument 123: must be a string label from list_browsers"))
        self.assertEqual(len(chrome_seen) + len(brave_seen), n_served, "the malformed call reached no browser")
        self.assertEqual(chrome_seen, [forwarded("tab_list", browser="chrome")] * 2,
                         "chrome served list_browsers' fan-out and its own call, each stamped chrome")
        self.assertEqual(brave_seen, [forwarded("tab_list", browser="brave")] * 2)

        h.kill(chrome)
        deadline = time.time() + 8
        while time.time() < deadline:
            listing = h.tool_payload(c.call("list_browsers", {}, _id=25))
            if listing["count"] == 1:
                break
            time.sleep(0.1)
        self.assertEqual(listing, {"browsers": [{"label": "brave", "tabCount": 1}], "count": 1})
        self.assertEqual(c.call("tab_list", {}, _id=26), tool_result(26, brave_tabs),
                         "an unaddressed call routes to the sole remaining browser")
        self.assertEqual(c.call("tab_list", {"browser": "chrome"}, _id=27),
                         tool_error(27, "BROWSER_NOT_FOUND", h.browser_not_found("chrome", ["brave"])))
        self.assertEqual((chrome_box["error"], brave_box["error"]), (None, None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
