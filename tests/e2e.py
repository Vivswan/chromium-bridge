#!/usr/bin/env python3
"""End-to-end integration tests for browser-bridge.

These tests drive the release binary as real subprocesses:
  - MCP server mode (default), spoken to over JSON-RPC/stdio
  - --native-host mode, spoken to with real Chrome Native-Messaging frames
  - tool round-trips that flow MCP client -> server -> real --native-host
    subprocess -> "extension" (us, speaking NM frames to the host) and back

Only the real browser-bridge binary can speak the bridge socket now: the MCP
server kernel-attests each peer's executable (ADR-0020), so a foreign process
cannot connect as a fake extension. The round-trip tests therefore route
through a real --native-host subprocess (which passes attestation because it is
the same binary), and test_foreign_peer_is_rejected confirms that a non-binary
peer connecting straight to the socket is refused.

They cover the protocol layers (NM framing, MCP JSON-RPC, bridge socket) and
the request/response correlation, including the new page_eval tool path.

Run:
    python3 tests/e2e.py
Exits 0 on success, 1 on any failure. Requires the release binary at
target/release/browser-bridge (will build it if missing via cargo).

This is an orchestration test (not a Rust #[test]) on purpose: it exercises
the full process boundary the way an MCP client and Chrome would, which a unit
test inside the crate cannot.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(REPO, "target", "release", "browser-bridge" + (".exe" if os.name == "nt" else ""))
# Mirror the binary's LockFile::path() (src/ipc.rs).
_XDG = os.environ.get("XDG_RUNTIME_DIR")
if os.name == "nt":
    _LOCAL = os.environ.get("LOCALAPPDATA", os.path.expanduser("~/AppData/Local"))
    LOCK = os.path.join(_LOCAL, "browser-bridge", "run.lock")
elif sys.platform == "darwin":
    LOCK = (
        os.path.join(_XDG, "browser-bridge", "run.lock")
        if _XDG
        else os.path.expanduser("~/Library/Application Support/browser-bridge/run.lock")
    )
else:
    _CACHE = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    LOCK = os.path.join(_XDG, "browser-bridge", "run.lock") if _XDG else os.path.join(
        _CACHE, "browser-bridge", "run.lock"
    )

_passed = 0
_failed = 0


def check(cond, label):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}")


def ensure_binary():
    if os.path.exists(BIN):
        return
    print("[setup] release binary missing, building…")
    cargo = "/opt/homebrew/bin/cargo"
    if not os.path.exists(cargo):
        cargo = "cargo"
    env = dict(os.environ, PATH="/opt/homebrew/bin:" + os.environ.get("PATH", ""))
    subprocess.check_call([cargo, "build", "--release", "--manifest-path",
                           os.path.join(REPO, "Cargo.toml")], env=env)


def wait_lock(proc=None, timeout=8):
    """Wait for the lock file and return its contents. If `proc` is given,
    require the lock to belong to it (lock["pid"] == proc.pid) — this ignores a
    stale lock from a previous test's server that hasn't finished exiting, which
    would otherwise point us at a dead port. Tolerates transient read errors."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with open(LOCK) as f:
                lf = json.load(f)
            if proc is None or lf.get("pid") == proc.pid:
                return lf
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    return None


def nm_write(p, obj):
    data = json.dumps(obj).encode()
    p.stdin.write(struct.pack("<I", len(data)) + data)
    p.stdin.flush()


def nm_read(p):
    hdr = p.stdout.read(4)
    if len(hdr) < 4:
        return None
    (n,) = struct.unpack("<I", hdr)
    return json.loads(p.stdout.read(n))


class McpClient:
    """Minimal MCP JSON-RPC client over stdio to the server subprocess."""

    def __init__(self, proc):
        self.proc = proc

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def recv(self):
        return json.loads(self.proc.stdout.readline())

    def initialize(self):
        self.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "e2e", "version": "0.1"}}})
        r = self.recv()
        return r

    def initialized(self):
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def ping(self, _id=99):
        self.send({"jsonrpc": "2.0", "id": _id, "method": "ping"})
        return self.recv()

    def tools_list(self, _id=2):
        self.send({"jsonrpc": "2.0", "id": _id, "method": "tools/list"})
        return self.recv()

    def call(self, name, args, _id=3):
        self.send({"jsonrpc": "2.0", "id": _id, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
        return self.recv()


def connect_bridge(lf, timeout=5):
    """Open a raw connection to the bridge socket (Unix-domain on Unix,
    loopback TCP on Windows). Used only by test_foreign_peer_is_rejected to
    simulate a non-browser-bridge process: a real extension never touches this
    socket, it talks Native-Messaging frames to a --native-host subprocess."""
    if os.name == "nt":
        host, port = lf["endpoint"].rsplit(":", 1)
        return socket.create_connection((host, int(port)), timeout=timeout)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(lf["endpoint"])
    return s


def start_bridge_host():
    """Spawn a real `browser-bridge --native-host`, the way Chrome does. It
    dials the server's bridge socket and passes peer attestation because it is
    the same binary; the server then drives it. The "extension" side (this test)
    speaks Native-Messaging frames to the host's stdin/stdout, which the host
    relays to and from the attested socket.

    A daemon thread drains the host's stderr and sets `nh.ready` when the host
    logs its handshake-complete marker, so callers wait on a real readiness
    signal (wait_host_ready) instead of guessing with a sleep. Draining also
    keeps the stderr pipe from filling during a test."""
    nh = subprocess.Popen([BIN, "--native-host"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nh.ready = threading.Event()

    def drain_stderr():
        for line in nh.stderr:
            if b"bridge handshake complete" in line:
                nh.ready.set()

    threading.Thread(target=drain_stderr, daemon=True).start()
    return nh


def wait_host_ready(nh, timeout=5):
    """Block until the native host reports a completed bridge handshake, or fail
    loudly on timeout (that is a real regression, not something to sleep past).
    On timeout, reap the host so a failing test does not leak the subprocess."""
    if not nh.ready.wait(timeout):
        nh.kill()
        try:
            nh.wait(timeout=3)
        except Exception:
            pass
        raise TimeoutError(
            f"native host did not complete the bridge handshake within {timeout}s")


def serve_bridge_req(nh, responder):
    """Read one BridgeReq the server forwarded (delivered as an NM frame on the
    host's stdout), hand it to `responder(req) -> dict`, and write the reply
    back as an NM frame to the host's stdin. Returns the request, or None on
    EOF."""
    req = nm_read(nh)
    if req is None:
        return None
    nm_write(nh, responder(req))
    return req


def test_mcp_handshake_and_tools():
    print("\n[test] MCP handshake + tools/list + ping")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written on startup")
        c = McpClient(mcp)
        init = c.initialize()
        check(init.get("result", {}).get("protocolVersion") == "2025-06-18",
              "initialize returns protocolVersion 2025-06-18")
        check("tools" in init.get("result", {}).get("capabilities", {}),
              "capabilities advertises tools")
        c.initialized()
        ping = c.ping()
        check(ping.get("result") == {}, "ping returns empty result")
        tools = c.tools_list()
        names = [t["name"] for t in tools["result"]["tools"]]
        check("tab_list" in names, "tools/list includes tab_list")
        check("page_eval" in names, "tools/list includes page_eval")
        check("page_snapshot_precise" in names, "tools/list includes page_snapshot_precise")
        # page_eval description must carry a HIGH RISK warning
        ev = next(t for t in tools["result"]["tools"] if t["name"] == "page_eval")
        check("HIGH RISK" in ev["description"], "page_eval description warns HIGH RISK")
        check(ev["inputSchema"]["required"] == ["code"], "page_eval requires code arg")
        # precise snapshot description must warn about the debugger banner
        ps = next(t for t in tools["result"]["tools"] if t["name"] == "page_snapshot_precise")
        check("debugger" in ps["description"].lower(),
              "page_snapshot_precise description mentions debugger")
        check("cookie_get" in names, "tools/list includes cookie_get")
        check("storage_get" in names, "tools/list includes storage_get")
        # cookie_get description must mention httpOnly + read-only
        ck = next(t for t in tools["result"]["tools"] if t["name"] == "cookie_get")
        check("httpOnly" in ck["description"], "cookie_get description mentions httpOnly")
        check("masked" in ck["description"].lower(), "cookie_get description mentions masking")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_stale_lock_is_replaced():
    print("\n[test] stale lock file is replaced on startup")
    os.makedirs(os.path.dirname(LOCK), exist_ok=True)
    with open(LOCK, "w", encoding="utf-8") as f:
        json.dump({"endpoint": "/nonexistent/browser-bridge/run.sock",
                   "secret": "0" * 32, "pid": 4294967295}, f)
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lock = wait_lock(mcp)
        check(lock is not None and lock.get("pid") == mcp.pid,
              "server replaced a dead process's lock file")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_tab_list_round_trip():
    print("\n[test] tab_list round-trip via real native host")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")

        def responder(req):
            assert req["op"] == "tab_list", f"unexpected op {req['op']}"
            return {"id": req["id"], "ok": True,
                    "data": [{"id": 7, "title": "E2E Tab", "url": "https://x", "active": True}]}

        nh = start_bridge_host()
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        wait_host_ready(nh)  # let the host connect, attest, and complete the handshake
        # serve the single tab_list request the call below will trigger
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()

        r = c.call("tab_list", {}, _id=5)
        t.join(timeout=3)
        check(bool(served), "native host received the tab_list BridgeReq")
        content = r["result"]["content"][0]["text"]
        data = json.loads(content)
        check(data[0]["title"] == "E2E Tab", "tab_list result carries host data")
        check(r["result"].get("isError") is False, "tab_list isError=false")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_page_eval_round_trip():
    print("\n[test] page_eval round-trip (op reaches extension)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")

        captured = {}

        def responder(req):
            captured["req"] = req
            # Echo back a typical eval result after masking would have been
            # applied by the (real) content script. Here we just verify the
            # op + code were forwarded correctly.
            return {"id": req["id"], "ok": True,
                    "data": {"result": 42, "masked": "••••[jwt]"}}

        nh = start_bridge_host()
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        wait_host_ready(nh)  # let the host connect, attest, and complete the handshake
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()

        r = c.call("page_eval", {"code": "return 1 + 41"}, _id=7)
        t.join(timeout=3)
        check(bool(served), "page_eval BridgeReq reached extension")
        check(captured.get("req", {}).get("op") == "page_eval",
              "forwarded op is page_eval")
        check(captured.get("req", {}).get("args", {}).get("code") == "return 1 + 41",
              "forwarded args.code matches input")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content.get("result") == 42, "eval result data returned to client")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_page_snapshot_precise_round_trip():
    print("\n[test] page_snapshot_precise round-trip (op reaches extension)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")
        captured = {}

        def responder(req):
            captured["req"] = req
            # Mirror what a real SW would return after the CDP round-trip:
            # refs with the 'p' prefix, precise: true.
            return {"id": req["id"], "ok": True, "data": {
                "refCount": 2,
                "nodes": [
                    {"ref": "p1", "role": "textbox", "name": "Search",
                     "selector": "input#q", "value": ""},
                    {"ref": "p2", "role": "button", "name": "Submit",
                     "selector": "button#go", "value": None},
                ],
                "url": "https://example.com",
                "title": "Example",
                "precise": True,
            }}

        nh = start_bridge_host()
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        wait_host_ready(nh)  # let the host connect, attest, and complete the handshake
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()

        r = c.call("page_snapshot_precise", {}, _id=9)
        t.join(timeout=3)
        check(bool(served), "page_snapshot_precise BridgeReq reached extension")
        check(captured.get("req", {}).get("op") == "page_snapshot_precise",
              "forwarded op is page_snapshot_precise")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content.get("precise") is True, "result carries precise:true flag")
        check(content["nodes"][0]["ref"] == "p1", "precise refs use 'p' prefix")
        check(len(content["nodes"]) == 2, "both nodes returned")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_cookie_get_round_trip():
    print("\n[test] cookie_get round-trip (op + args reach extension)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")
        captured = {}

        def responder(req):
            captured["req"] = req
            # Mirror what background.js cookieGet returns: cookies with masked
            # values but preserved structure fields.
            return {"id": req["id"], "ok": True, "data": {
                "cookies": [
                    {"name": "session", "value": "••••[jwt]", "domain": ".example.com",
                     "path": "/", "httpOnly": True, "secure": True,
                     "sameSite": "lax", "session": False},
                ],
                "count": 1,
            }}

        nh = start_bridge_host()
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        wait_host_ready(nh)  # let the host connect, attest, and complete the handshake
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()

        r = c.call("cookie_get", {"url": "https://example.com"}, _id=10)
        t.join(timeout=3)
        check(bool(served), "cookie_get BridgeReq reached extension")
        check(captured.get("req", {}).get("op") == "cookie_get",
              "forwarded op is cookie_get")
        check(captured["req"]["args"].get("url") == "https://example.com",
              "forwarded args.url matches")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content["cookies"][0]["httpOnly"] is True,
              "cookie structure (httpOnly) preserved")
        check("••••" in content["cookies"][0]["value"],
              "cookie value is masked")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_storage_get_round_trip():
    print("\n[test] storage_get round-trip (op reaches extension)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")
        captured = {}

        def responder(req):
            captured["req"] = req
            return {"id": req["id"], "ok": True, "data": {
                "key": "auth_token",
                "found": True,
                "value": "••••[jwt]",
            }}

        nh = start_bridge_host()
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        wait_host_ready(nh)  # let the host connect, attest, and complete the handshake
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()

        r = c.call("storage_get", {"type": "local", "key": "auth_token"}, _id=11)
        t.join(timeout=3)
        check(bool(served), "storage_get BridgeReq reached extension")
        check(captured.get("req", {}).get("op") == "storage_get",
              "forwarded op is storage_get")
        check(captured["req"]["args"].get("key") == "auth_token",
              "forwarded args.key matches")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content.get("found") is True, "storage result has found:true")
        check("••••" in content.get("value", ""), "storage value is masked")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_native_host_mode():
    print("\n[test] --native-host mode with real NM framing")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")
        # Launch --native-host the way Chrome would; it dials the bridge and
        # attests. Binary mode (no text=True) since NM framing is raw bytes.
        nh = start_bridge_host()
        wait_host_ready(nh)  # let it connect, attest, and complete the handshake

        c = McpClient(mcp)
        c.initialize()
        c.initialized()

        # Send the tools/call request ourselves (don't read the response yet).
        c.send({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})

        # The MCP server forwards it over the bridge socket -> native host ->
        # stdout as an NM frame.
        frame = nm_read(nh)
        check(frame is not None and frame.get("op") == "tab_list",
              "native host emits BridgeReq as NM frame to extension")

        # Extension replies: NM frame -> native host stdin -> bridge socket -> MCP.
        nm_write(nh, {"id": frame["id"], "ok": True,
                      "data": [{"id": 1, "title": "NM Round Trip", "url": "y", "active": True}]})

        # Now the MCP server resolves and writes the tools/call response to stdout.
        r = c.recv()
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "NM Round Trip",
              "extension reply traveled host -> MCP -> client")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=5)


def test_enclave_control_frames():
    """The native host must answer enclave control frames itself (ADR-0021)
    and never forward them over the bridge socket. Only challenges that fail
    validation BEFORE any keychain access are sent here, so this test never
    raises a Touch ID prompt even on a machine that has run `pair`; the
    well-formed signing path is presence-gated by design and covered by the
    manual test script (docs/security/enrollment-manual-test.md)."""
    print("\n[test] enclave control frames are answered locally, not forwarded")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        nh = start_bridge_host()
        wait_host_ready(nh)

        # A challenge whose nonce fails validation (embedded NUL) is answered
        # by the host with enclave_error/invalid_challenge — locally, without
        # touching the keychain.
        nm_write(nh, {"type": "enclave_challenge", "nonce": "bad\x00nonce"})
        reply = nm_read(nh)
        check(reply is not None and reply.get("type") == "enclave_error",
              "invalid challenge answered with enclave_error")
        check(reply is not None and reply.get("reason") == "invalid_challenge",
              "reason is invalid_challenge")

        # A structurally malformed control frame (missing nonce) also gets a
        # local invalid_challenge error rather than being forwarded.
        nm_write(nh, {"type": "enclave_challenge"})
        reply = nm_read(nh)
        check(reply is not None and reply.get("type") == "enclave_error"
              and reply.get("reason") == "invalid_challenge",
              "malformed control frame answered locally")

        # A stray proof frame is dropped: no reply, and the pump keeps
        # working. Prove both with a normal tool round trip afterwards — if
        # the stray frame had been forwarded, it would desynchronize the
        # bridge correlation and this round trip would fail.
        nm_write(nh, {"type": "enclave_proof", "sig": "x", "key_id": "y",
                      "pubkey": "z"})
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        c.send({"jsonrpc": "2.0", "id": 31, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        frame = nm_read(nh)
        check(frame is not None and frame.get("op") == "tab_list",
              "pump still forwards ordinary frames after control traffic")
        nm_write(nh, {"id": frame["id"], "ok": True,
                      "data": [{"id": 1, "title": "After Control", "url": "u",
                                "active": True}]})
        r = c.recv()
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "After Control",
              "round trip completes; stray proof frame was dropped, not forwarded")
        nh.kill()
        nh.wait(timeout=3)
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=5)


def test_server_takeover():
    print("\n[test] new MCP server supplants the previous server")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    first = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8")
    second = None
    try:
        first_lock = wait_lock(first)
        check(first_lock is not None, "first server wrote its lock file")
        second = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8")
        second_lock = wait_lock(second)
        check(second_lock is not None, "second server replaced the lock file")
        first.wait(timeout=8)
        check(first.poll() is not None, "previous server was terminated")
    finally:
        if first.poll() is None:
            first.kill()
        if second is not None:
            try:
                second.stdin.close()
            except Exception:
                pass
            second.wait(timeout=3)


def test_takeover_leaves_new_socket_connectable():
    """Regression: the takeover used to run AFTER the new server bound its
    socket, and the supplant path (plus the dying server's own cleanup)
    unlinked that freshly-bound socket. The new listener stayed bound to an
    unlinked inode, the reconnecting native host got ENOENT, and the bridge
    reported "extension not connected" until everything was restarted by
    hand. This drives the exact sequence: live server, takeover by a second
    server, then a real native host must reach the NEW server's socket and a
    tool call must round-trip through it.

    NOTE: this proves the socket/lock/reconnect leg at the process level. The
    full loop (Chrome observing the port close and the extension's service
    worker re-spawning the host) still needs an isolated browser to confirm.
    """
    print("\n[test] after takeover, a native host reaches the new server's socket")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    first = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8")
    second = None
    nh = None
    try:
        check(wait_lock(first) is not None, "first server wrote its lock file")
        # Keep the first server ALIVE (stdin open) so this is a real takeover
        # of a running instance, not a stale-lock cleanup.
        second = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8")
        second_lock = wait_lock(second)
        check(second_lock is not None, "second server wrote its lock file")
        first.wait(timeout=8)
        check(first.poll() is not None, "first server was terminated")
        if os.name != "nt":
            check(os.path.exists(second_lock["endpoint"]),
                  "new server's socket path exists on disk after the takeover")

        # The reconnect: a fresh native host (as Chrome would spawn) must be
        # able to dial, attest, and complete the handshake against the NEW
        # server. Before the fix this failed with ENOENT on the socket.
        nh = start_bridge_host()
        try:
            wait_host_ready(nh)
            check(True, "native host completed the handshake with the new server")
        except TimeoutError:
            nh = None  # wait_host_ready already reaped it
            check(False, "native host completed the handshake with the new server")
            return

        # And a full tool round-trip through the post-takeover server.
        def responder(req):
            return {"id": req["id"], "ok": True,
                    "data": [{"id": 1, "title": "Takeover OK", "url": "z", "active": True}]}

        c = McpClient(second)
        c.initialize()
        c.initialized()
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()
        r = c.call("tab_list", {}, _id=12)
        t.join(timeout=3)
        check(bool(served), "tab_list BridgeReq reached the host via the new socket")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "Takeover OK",
              "tool call round-trips through the post-takeover server")
    finally:
        if nh is not None:
            nh.kill()
            try:
                nh.wait(timeout=3)
            except Exception:
                pass
        if first.poll() is None:
            first.kill()
        if second is not None:
            try:
                second.stdin.close()
            except Exception:
                pass
            second.wait(timeout=3)


def test_concurrent_server_starts_settle_to_one_working_bridge():
    """Several servers starting at once must settle to exactly one owner whose
    socket a native host can actually reach. The publish step is serialized by
    a kernel file lock (ipc::RuntimeMutex) and re-checks the lock owner, so
    racing servers supplant each other in turn instead of unlinking each
    other's freshly-bound sockets; losers either get terminated or give up
    after bounded retries."""
    print("\n[test] concurrent server starts settle to one working bridge")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    servers = [subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8")
               for _ in range(4)]
    nh = None
    try:
        # Let the takeover churn settle: eventually exactly one server remains,
        # and the lock on disk names it.
        deadline = time.time() + 20
        alive = servers
        lf = None
        while time.time() < deadline:
            alive = [s for s in servers if s.poll() is None]
            if len(alive) == 1:
                lf = wait_lock(alive[0], timeout=2)
                if lf is not None:
                    break
            time.sleep(0.2)
        check(len(alive) == 1, f"exactly one server survives ({len(alive)} alive)")
        if len(alive) != 1:
            return
        winner = alive[0]
        check(lf is not None and lf.get("pid") == winner.pid,
              "lock file names the surviving server")
        if os.name != "nt":
            check(os.path.exists(lf["endpoint"]), "survivor's socket path exists")

        nh = start_bridge_host()
        try:
            wait_host_ready(nh)
            check(True, "native host completed the handshake with the survivor")
        except TimeoutError:
            nh = None
            check(False, "native host completed the handshake with the survivor")
            return

        def responder(req):
            return {"id": req["id"], "ok": True,
                    "data": [{"id": 2, "title": "Survivor OK", "url": "w", "active": True}]}

        c = McpClient(winner)
        c.initialize()
        c.initialized()
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()
        r = c.call("tab_list", {}, _id=13)
        t.join(timeout=3)
        check(bool(served), "tab_list round-trips through the surviving server")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "Survivor OK", "survivor returned the host's data")
    finally:
        if nh is not None:
            nh.kill()
            try:
                nh.wait(timeout=3)
            except Exception:
                pass
        for s in servers:
            if s.poll() is None:
                try:
                    s.stdin.close()
                except Exception:
                    pass
                try:
                    s.wait(timeout=3)
                except Exception:
                    s.kill()


def test_unknown_method_returns_32601():
    print("\n[test] unknown method returns JSON-RPC -32601")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        c.send({"jsonrpc": "2.0", "id": 11, "method": "resources/list"})
        r = c.recv()
        check(r.get("error", {}).get("code") == -32601,
              "unknown method -> error code -32601")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_foreign_peer_is_rejected():
    print("\n[test] a foreign (non-browser-bridge) peer is refused by attestation")
    if os.name == "nt":
        print("  SKIP  attestation is Unix-only (Windows keeps loopback TCP)")
        return
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")
        # Connect a raw python process straight to the bridge socket. It is not
        # the browser-bridge binary, so server-side executable attestation must
        # drop it BEFORE sending any HMAC challenge: our recv sees a clean EOF.
        s = connect_bridge(lf)
        s.settimeout(3)
        try:
            data = s.recv(4096)
        except socket.timeout:
            data = b"__no_eof__"
        check(data == b"",
              "server dropped the foreign peer without a challenge")
        s.close()
        # Prove the drop was attestation specifically (not a uid check, a bind
        # error, or some other cause): the server logs the executable-identity
        # mismatch to stderr. Draining stdin ends the server so we can read it.
        mcp.stdin.close()
        try:
            _out, err = mcp.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            mcp.kill()
            _out, err = mcp.communicate()
        check("identity mismatch" in (err or ""),
              "server logged an executable-identity mismatch (attestation fired)")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        try:
            mcp.wait(timeout=3)
        except Exception:
            pass


def main():
    ensure_binary()
    print(f"binary: {BIN}")
    test_stale_lock_is_replaced()
    test_mcp_handshake_and_tools()
    test_tab_list_round_trip()
    test_page_eval_round_trip()
    test_page_snapshot_precise_round_trip()
    test_cookie_get_round_trip()
    test_storage_get_round_trip()
    test_native_host_mode()
    test_enclave_control_frames()
    test_foreign_peer_is_rejected()
    test_server_takeover()
    test_takeover_leaves_new_socket_connectable()
    test_concurrent_server_starts_settle_to_one_working_bridge()
    test_unknown_method_returns_32601()
    print(f"\n{'='*40}\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
