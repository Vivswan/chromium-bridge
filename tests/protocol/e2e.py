#!/usr/bin/env python3
"""End-to-end integration tests for chromium-bridge.

These tests drive the release binary as real subprocesses:
  - MCP server mode (default), spoken to over JSON-RPC/stdio
  - --native-host mode, spoken to with real Chrome Native-Messaging frames
  - tool round-trips that flow MCP client -> server -> real --native-host
    subprocess -> "extension" (us, speaking NM frames to the host) and back

Only the real chromium-bridge binary can speak the bridge socket now: the MCP
server kernel-attests each peer's executable (ADR-0020), so a foreign process
cannot connect as a fake extension. The round-trip tests therefore route
through a real --native-host subprocess (which passes attestation because it is
the same binary), and test_foreign_peer_is_rejected confirms that a non-binary
peer connecting straight to the socket is refused.

They cover the protocol layers (NM framing, MCP JSON-RPC, bridge socket) and
the request/response correlation, including the new page_eval tool path.

Run:
    python3 tests/protocol/e2e.py
Exits 0 on success, 1 on any failure. Requires the release binary at
target/release/chromium-bridge (will build it if missing via cargo).

This is an orchestration test (not a Rust #[test]) on purpose: it exercises
the full process boundary the way an MCP client and Chrome would, which a unit
test inside the crate cannot.
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(REPO, "target", "release", "chromium-bridge" + (".exe" if os.name == "nt" else ""))
# Mirror the binary's LockFile::path() (src/ipc.rs).
_XDG = os.environ.get("XDG_RUNTIME_DIR")
if os.name == "nt":
    _LOCAL = os.environ.get("LOCALAPPDATA", os.path.expanduser("~/AppData/Local"))
    LOCK = os.path.join(_LOCAL, "chromium-bridge", "run.lock")
elif sys.platform == "darwin":
    LOCK = (
        os.path.join(_XDG, "chromium-bridge", "run.lock")
        if _XDG
        else os.path.expanduser("~/Library/Application Support/chromium-bridge/run.lock")
    )
else:
    _CACHE = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    LOCK = os.path.join(_XDG, "chromium-bridge", "run.lock") if _XDG else os.path.join(
        _CACHE, "chromium-bridge", "run.lock"
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
    print("[setup] release binary missing, building...")
    cargo = "/opt/homebrew/bin/cargo"
    if not os.path.exists(cargo):
        cargo = "cargo"
    env = dict(os.environ, PATH="/opt/homebrew/bin:" + os.environ.get("PATH", ""))
    subprocess.check_call([cargo, "build", "--release", "--manifest-path",
                           os.path.join(REPO, "Cargo.toml")], env=env)


def wait_lock(proc=None, timeout=8):
    """Wait for the lock file and return its contents. If `proc` is given,
    require the lock to belong to it (lock["pid"] == proc.pid) - this ignores a
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
    simulate a non-chromium-bridge process: a real extension never touches this
    socket, it talks Native-Messaging frames to a --native-host subprocess."""
    if os.name == "nt":
        host, port = lf["endpoint"].rsplit(":", 1)
        return socket.create_connection((host, int(port)), timeout=timeout)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(lf["endpoint"])
    return s


def start_bridge_host(label=None, env=None):
    """Spawn a real `chromium-bridge --native-host`, the way Chrome does. It
    dials the server's bridge socket and passes peer attestation because it is
    the same binary; the server then drives it. The "extension" side (this test)
    speaks Native-Messaging frames to the host's stdin/stdout, which the host
    relays to and from the attested socket.

    `label` is passed as `--label` (the per-browser identity the installer
    bakes into each browser's wrapper); None mirrors a pre-label wrapper and
    lands in the server's "default" slot. `env` overrides the child environment
    (used by the isolated admin/revocation tests to steer the runtime dir).

    A daemon thread drains the host's stderr and sets `nh.ready` when the host
    logs its handshake-complete marker, so callers wait on a real readiness
    signal (wait_host_ready) instead of guessing with a sleep. Draining also
    keeps the stderr pipe from filling during a test."""
    cmd = [BIN, "--native-host"]
    if label is not None:
        cmd += ["--label", label]
    nh = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
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


def serve_bridge_loop(nh, responder):
    """Keep serving BridgeReqs on `nh` from a daemon thread until the host's
    stdout closes (host killed or test over). Used by the multi-browser test,
    where the number of requests a given host will see is not known up front
    (list_browsers fans out one tab_list per live browser).

    Returns a box dict: `box["error"]` carries any unexpected exception from
    the responder thread (daemon-thread exceptions would otherwise vanish),
    and the caller must check it before the test ends."""
    box = {"error": None, "thread": None}

    def loop():
        try:
            while serve_bridge_req(nh, responder) is not None:
                pass
        except (ValueError, OSError):
            pass  # host torn down mid-read; the test is done with it
        except Exception as e:  # noqa: BLE001 - surfaced via box in the main thread
            box["error"] = e

    box["thread"] = threading.Thread(target=loop, daemon=True)
    box["thread"].start()
    return box


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
        json.dump({"endpoint": "/nonexistent/chromium-bridge/run.sock",
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
        # by the host with enclave_error/invalid_challenge - locally, without
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
        # working. Prove both with a normal tool round trip afterwards - if
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


def test_admin_control_frames():
    """The native host answers the ADR-0025 trusted-client admin frames itself
    (client_list / client_revoke) and never forwards them over the bridge
    socket, mirroring the enclave control frames. Uses an isolated runtime dir
    (never the developer's real clients.json) via a private XDG_RUNTIME_DIR, so
    pairing and revoking here cannot touch real state."""
    print("\n[test] trusted-client admin frames are answered locally (ADR-0025)")
    rundir = tempfile.mkdtemp(prefix="bb-admin-e2e-")
    env = dict(os.environ, XDG_RUNTIME_DIR=rundir,
               XDG_CONFIG_HOME=os.path.join(rundir, "config"))
    if sys.platform == "darwin":
        env["HOME"] = rundir
    lock = os.path.join(rundir, "chromium-bridge", "run.lock")
    global LOCK
    saved_lock = LOCK
    LOCK = lock
    mcp = None
    nh = None
    try:
        # Pair this test's own process so the server it spawns is admitted
        # (admission is enforced once any client is paired), plus a separate
        # trusted client the admin frames will enumerate and revoke.
        subprocess.run([BIN, "pair-client", "--name", "pytest", "--this-parent"],
                       check=True, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run([BIN, "pair-client", "--name", "codex", "--hash", "aa" * 32],
                       check=True, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)
        wait_lock(mcp)
        nh = start_bridge_host(env=env)
        wait_host_ready(nh)

        # client_list is answered by the HOST, never forwarded to the server.
        nm_write(nh, {"type": "client_list"})
        reply = nm_read(nh)
        check(reply is not None and reply.get("type") == "client_list_result"
              and reply.get("ok") is True and reply.get("enrolled") is True,
              "client_list answered locally with the enrolled list")
        names = sorted(c["name"] for c in reply.get("clients", [])) if reply else []
        check(names == ["codex", "pytest"], "the list carries both paired clients")

        # client_revoke removes the codex entry and is acknowledged locally.
        nm_write(nh, {"type": "client_revoke", "name": "codex"})
        reply = nm_read(nh)
        check(reply is not None and reply.get("type") == "client_revoke_result"
              and reply.get("ok") is True, "client_revoke acknowledged ok")

        # A stray result frame from the browser side is dropped (never
        # forwarded): prove the pump still forwards ordinary traffic after it.
        nm_write(nh, {"type": "client_list_result", "ok": True, "enrolled": True,
                      "clients": []})
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        c.send({"jsonrpc": "2.0", "id": 71, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        frame = nm_read(nh)
        check(frame is not None and frame.get("op") == "tab_list",
              "pump still forwards ordinary frames after admin control traffic")
        nm_write(nh, {"id": frame["id"], "ok": True,
                      "data": [{"id": 1, "title": "After Admin", "url": "u",
                                "active": True}]})
        r = c.recv()
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "After Admin",
              "round trip completes; stray result frame was dropped, not forwarded")
        nh.kill()
        nh.wait(timeout=3)
        nh = None
    finally:
        if nh is not None and nh.poll() is None:
            nh.kill()
            try:
                nh.wait(timeout=3)
            except Exception:
                pass
        if mcp is not None:
            try:
                mcp.stdin.close()
            except Exception:
                pass
            mcp.wait(timeout=5)
        LOCK = saved_lock
        shutil.rmtree(rundir, ignore_errors=True)


def test_second_instance_coexists_as_relay():
    """Coexistence (ADR-0024): a second MCP-server instance does NOT SIGTERM the
    first (newest-wins takeover is gone). The first instance is the broker and
    keeps owning the lock; the second attests it and attaches as a relay. Both
    stay alive and both can drive the bridge over their own stdio."""
    print("\n[test] a second instance coexists as a relay (no takeover)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    first = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8")
    second = None
    try:
        first_lock = wait_lock(first)
        check(first_lock is not None, "first instance became the broker and wrote the lock")
        second = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8")
        # Give the relay a moment to attest, handshake, and attach.
        time.sleep(1.0)
        check(first.poll() is None, "broker is NOT terminated by the second instance")
        check(second.poll() is None, "second instance stays alive as a relay")
        still = wait_lock(first, timeout=2)
        check(still is not None and still.get("pid") == first.pid,
              "the lock still names the original broker (not replaced)")
        # Both harnesses answer over their own stdio: the broker directly, the
        # relay transparently over the authenticated socket.
        cb = McpClient(first)
        check("result" in cb.initialize(), "broker harness initializes")
        cr = McpClient(second)
        check("result" in cr.initialize(), "relay harness initializes over the broker")
        check(cr.ping(_id=77).get("result") == {}, "relay harness pings via the broker")
    finally:
        for p in (second, first):
            if p is not None and p.poll() is None:
                try:
                    p.stdin.close()
                except Exception:
                    pass
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()


def test_two_harnesses_drive_one_browser():
    """The core multi-client win: a broker and a relay, both attached to one
    browser, drive it concurrently. Each harness's tool call routes through the
    shared session to the single native host, which answers both."""
    print("\n[test] two harnesses (broker + relay) drive one browser concurrently")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    first = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8")
    second = None
    nh = None
    try:
        check(wait_lock(first) is not None, "broker wrote the lock")
        second = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8")
        time.sleep(1.0)
        check(second.poll() is None, "relay attached")

        nh = start_bridge_host()
        wait_host_ready(nh)
        check(True, "one native host attached to the broker")

        def responder(req):
            return {"id": req["id"], "ok": True,
                    "data": [{"id": 1, "title": "Shared", "url": "z", "active": True}]}
        box = serve_bridge_loop(nh, responder)

        cb = McpClient(first)
        cb.initialize(); cb.initialized()
        cr = McpClient(second)
        cr.initialize(); cr.initialized()

        rb = cb.call("tab_list", {}, _id=21)
        rr = cr.call("tab_list", {}, _id=22)
        cb_content = json.loads(rb["result"]["content"][0]["text"])
        cr_content = json.loads(rr["result"]["content"][0]["text"])
        check(cb_content[0]["title"] == "Shared", "broker harness reached the browser")
        check(cr_content[0]["title"] == "Shared", "relay harness reached the same browser")
        check(box["error"] is None, f"browser responder clean ({box['error']!r})")
    finally:
        if nh is not None and nh.poll() is None:
            nh.kill()
            try:
                nh.wait(timeout=3)
            except Exception:
                pass
        for p in (second, first):
            if p is not None and p.poll() is None:
                try:
                    p.stdin.close()
                except Exception:
                    pass
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()


def test_broker_is_ref_counted():
    """The broker is ref-counted (ADR-0024): it exits when the LAST harness
    (its own plus every relay) detaches, and it OUTLIVES its own harness while a
    relay is still attached. No idle daemon, but no premature exit either."""
    print("\n[test] the broker is ref-counted (outlives own harness, exits on last detach)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass

    # Part A: a lone broker exits when its own (only) harness detaches.
    solo = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        check(wait_lock(solo) is not None, "lone broker wrote the lock")
        solo.stdin.close()
        solo.wait(timeout=8)
        check(solo.poll() is not None, "lone broker exits when its only harness detaches")
        check(not os.path.exists(LOCK), "lone broker removed its lock on exit")
    finally:
        if solo.poll() is None:
            solo.kill()

    # Part B: broker + relay. Detaching the broker's OWN harness must NOT exit
    # the broker while the relay is attached; only the relay leaving ends it.
    first = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8")
    second = None
    try:
        first_lock = wait_lock(first)
        check(first_lock is not None, "broker wrote the lock")
        second = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, encoding="utf-8")
        time.sleep(1.0)
        check(second.poll() is None, "relay attached")

        # Detach the broker's own harness. The broker must keep serving the relay.
        first.stdin.close()
        time.sleep(1.0)
        check(first.poll() is None, "broker OUTLIVES its own harness while a relay is attached")
        still = wait_lock(first, timeout=2)
        check(still is not None and still.get("pid") == first.pid,
              "the broker still owns the lock after its own harness left")
        check(McpClient(second).ping(_id=88).get("result") == {},
              "relay still works after the broker's own harness detached")

        # Now the last harness (the relay) leaves: the broker exits and cleans up.
        second.stdin.close()
        first.wait(timeout=10)
        check(first.poll() is not None, "broker exits once the LAST harness detaches")
        check(not os.path.exists(LOCK), "broker removed its lock on final exit")
    finally:
        for p in (second, first):
            if p is not None and p.poll() is None:
                p.kill()


def test_concurrent_starts_coexist_and_all_drive_the_bridge():
    """Several instances starting at once settle to exactly one broker (owning
    the lock) plus relays, with ALL instances alive and able to drive one
    attached browser. Coexistence replaces the old newest-wins churn: no
    instance SIGTERMs another, and the RuntimeMutex still guarantees a single
    socket owner."""
    print("\n[test] concurrent starts coexist: one broker + relays, all drive the bridge")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    servers = [subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8")
               for _ in range(3)]
    nh = None
    try:
        # Settle: exactly one lock exists, naming a live instance, and every
        # instance is still alive (one broker + two relays).
        deadline = time.time() + 15
        lf = None
        while time.time() < deadline:
            alive = [s for s in servers if s.poll() is None]
            lf = wait_lock(timeout=1)
            if lf is not None and len(alive) == len(servers):
                break
            time.sleep(0.2)
        alive = [s for s in servers if s.poll() is None]
        check(len(alive) == len(servers),
              f"all {len(servers)} instances coexist ({len(alive)} alive)")
        check(lf is not None, "exactly one lock exists")
        owner_pids = [s.pid for s in servers if s.pid == (lf or {}).get("pid")]
        check(bool(owner_pids), "the lock names one of the instances (the broker)")

        nh = start_bridge_host()
        wait_host_ready(nh)
        check(True, "a native host attached to the broker")

        def responder(req):
            return {"id": req["id"], "ok": True,
                    "data": [{"id": 3, "title": "Coexist", "url": "w", "active": True}]}
        box = serve_bridge_loop(nh, responder)

        # Every instance (broker + each relay) drives the one browser.
        for i, s in enumerate(servers):
            c = McpClient(s)
            c.initialize(); c.initialized()
            r = c.call("tab_list", {}, _id=30 + i)
            content = json.loads(r["result"]["content"][0]["text"])
            check(content[0]["title"] == "Coexist", f"instance {i} drove the shared browser")
        check(box["error"] is None, f"browser responder clean ({box['error']!r})")
    finally:
        if nh is not None and nh.poll() is None:
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
    print("\n[test] a foreign (non-chromium-bridge) peer is refused by attestation")
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
        # the chromium-bridge binary, so server-side executable attestation must
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


def test_two_browsers():
    print("\n[test] two labeled browsers connect, are listed, and route independently")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    chrome = brave = None
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")
        c = McpClient(mcp)
        c.initialize()
        c.initialized()

        # Two real --native-host subprocesses, one per "browser". Each dials
        # the bridge, is attested, and completes its OWN HMAC handshake - the
        # ready events below fire per host, proving each connection was
        # authenticated independently rather than riding on the other's.
        chrome = start_bridge_host("chrome")
        brave = start_bridge_host("brave")
        wait_host_ready(chrome)
        wait_host_ready(brave)
        check(True, "both hosts authenticated independently (per-connection handshake)")

        # With two authenticated browsers attached, a foreign (non-binary)
        # peer is still rejected by attestation before any challenge.
        # (Executable attestation is Unix-only, like test_foreign_peer_is_rejected.)
        if os.name != "nt":
            s = connect_bridge(lf)
            s.settimeout(3)
            try:
                data = s.recv(4096)
            except socket.timeout:
                data = b"__no_eof__"
            check(data == b"", "foreign peer still refused while two browsers are live")
            s.close()

        # Each "extension" serves tab_list with distinct data and RECORDS the
        # envelope's browser stamp (the server's routing decision). Recording
        # instead of asserting keeps a mismatch from killing the responder
        # thread (which would turn one failure into a 120s hang); the main
        # thread asserts on the recordings below.
        def responder_for(tabs, seen):
            def responder(req):
                seen.append((req.get("op"), req.get("browser")))
                return {"id": req["id"], "ok": True, "data": tabs}
            return responder

        chrome_tabs = [{"id": 1, "title": "Chrome Tab", "url": "https://a", "active": True},
                       {"id": 2, "title": "Chrome Tab 2", "url": "https://b", "active": False}]
        brave_tabs = [{"id": 9, "title": "Brave Tab", "url": "https://c", "active": True}]
        chrome_seen, brave_seen = [], []
        chrome_box = serve_bridge_loop(chrome, responder_for(chrome_tabs, chrome_seen))
        brave_box = serve_bridge_loop(brave, responder_for(brave_tabs, brave_seen))

        # list_browsers enumerates both labels with their tab counts.
        r = c.call("list_browsers", {}, _id=20)
        listing = json.loads(r["result"]["content"][0]["text"])
        check(listing.get("count") == 2, "list_browsers reports two browsers")
        by_label = {b["label"]: b for b in listing.get("browsers", [])}
        check(set(by_label) == {"chrome", "brave"},
              "list_browsers shows both labels")
        check(by_label.get("chrome", {}).get("tabCount") == 2,
              "chrome entry counts its 2 tabs")
        check(by_label.get("brave", {}).get("tabCount") == 1,
              "brave entry counts its 1 tab")

        # Explicit routing: the same tool call reaches different browsers.
        r = c.call("tab_list", {"browser": "chrome"}, _id=21)
        data = json.loads(r["result"]["content"][0]["text"])
        check(data[0]["title"] == "Chrome Tab", "tab_list browser=chrome hits chrome")
        r = c.call("tab_list", {"browser": "brave"}, _id=22)
        data = json.loads(r["result"]["content"][0]["text"])
        check(data[0]["title"] == "Brave Tab", "tab_list browser=brave hits brave")

        # No browser argument while two are connected: a clear error, not a
        # guess (the model must not act in an arbitrary logged-in browser).
        r = c.call("tab_list", {}, _id=23)
        check(r["result"].get("isError") is True, "unaddressed call errors with two browsers")
        text = r["result"]["content"][0]["text"]
        check("BROWSER_AMBIGUOUS" in text, "ambiguity error carries BROWSER_AMBIGUOUS")
        check("brave" in text and "chrome" in text, "ambiguity error names the live labels")

        # An unknown label is refused, naming what IS connected.
        r = c.call("tab_list", {"browser": "edge"}, _id=24)
        check(r["result"].get("isError") is True, "unknown label errors")
        check("BROWSER_NOT_FOUND" in r["result"]["content"][0]["text"],
              "unknown label carries BROWSER_NOT_FOUND")

        # A malformed (non-string) browser argument is rejected up front -
        # it must not silently route anywhere.
        n_served = len(chrome_seen) + len(brave_seen)
        r = c.call("tab_list", {"browser": 123}, _id=28)
        check(r["result"].get("isError") is True, "non-string browser arg errors")
        check("INVALID_ARGUMENT" in r["result"]["content"][0]["text"],
              "non-string browser arg carries INVALID_ARGUMENT")
        check(len(chrome_seen) + len(brave_seen) == n_served,
              "the malformed call never reached any browser")

        # The envelope of every served request carried the label of exactly
        # the browser that served it (asserted here, in the main thread).
        check(bool(chrome_seen) and all(b == "chrome" for _, b in chrome_seen),
              "every request chrome served was stamped browser=chrome")
        check(bool(brave_seen) and all(b == "brave" for _, b in brave_seen),
              "every request brave served was stamped browser=brave")

        # Kill chrome (a process we started): the registry drops only that
        # entry, and routing collapses back to the sole remaining browser.
        chrome.kill()
        chrome.wait(timeout=3)
        deadline = time.time() + 8
        listing = None
        while time.time() < deadline:
            r = c.call("list_browsers", {}, _id=25)
            listing = json.loads(r["result"]["content"][0]["text"])
            if listing.get("count") == 1:
                break
            time.sleep(0.1)
        check(listing is not None and listing.get("count") == 1
              and listing["browsers"][0]["label"] == "brave",
              "after chrome exits, only brave remains listed")
        r = c.call("tab_list", {}, _id=26)
        data = json.loads(r["result"]["content"][0]["text"])
        check(data[0]["title"] == "Brave Tab",
              "unaddressed call now routes to the sole remaining browser")
        r = c.call("tab_list", {"browser": "chrome"}, _id=27)
        check("BROWSER_NOT_FOUND" in r["result"]["content"][0]["text"],
              "the departed browser's label is no longer routable")

        # Responder threads must have run clean (their exceptions are boxed,
        # not printed, so surface them here).
        check(chrome_box["error"] is None and brave_box["error"] is None,
              f"responder threads finished cleanly "
              f"(chrome={chrome_box['error']!r} brave={brave_box['error']!r})")

        brave.kill()
        brave.wait(timeout=3)
    finally:
        for nh in (chrome, brave):
            if nh is not None and nh.poll() is None:
                nh.kill()
                try:
                    nh.wait(timeout=3)
                except Exception:
                    pass
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=5)


def isolate():
    """Point every server this suite spawns at a private, empty runtime dir so
    its lock/socket and the broker's coexistence logic can NEVER touch the
    developer's real bridge. Mandatory: the standing rule is that no e2e/broker
    run uses the default user-level runtime dir. Recomputes LOCK to match."""
    global LOCK
    rundir = tempfile.mkdtemp(prefix="bb-e2e-")
    os.environ["XDG_RUNTIME_DIR"] = rundir
    os.environ["XDG_CONFIG_HOME"] = os.path.join(rundir, "config")
    if sys.platform == "darwin":
        os.environ["HOME"] = rundir
    LOCK = os.path.join(rundir, "chromium-bridge", "run.lock")
    if os.environ.get("XDG_RUNTIME_DIR") != rundir or not LOCK.startswith(rundir):
        sys.exit("REFUSING TO RUN: e2e runtime-dir isolation did not take")
    print(f"[isolation] per-run runtime dir: {rundir}")
    print(f"[isolation] lock path:           {LOCK}")


def main():
    ensure_binary()
    isolate()
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
    test_admin_control_frames()
    test_two_browsers()
    test_foreign_peer_is_rejected()
    test_second_instance_coexists_as_relay()
    test_two_harnesses_drive_one_browser()
    test_broker_is_ref_counted()
    test_concurrent_starts_coexist_and_all_drive_the_bridge()
    test_unknown_method_returns_32601()
    print(f"\n{'='*40}\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
