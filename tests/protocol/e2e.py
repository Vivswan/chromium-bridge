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
the request/response correlation, including the new page_eval tool path. The
MCP layer is exercised in both eras: modern 2026-07-28 requests (stamped with
the _meta protocol-version and client-capabilities keys) and the temporary
legacy era for bare requests on initialize-opened connections (its tests are
deleted when legacy-era support is dropped, ADR-0034).

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
import re
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
# Mirror the binary's LockFile::path() (src/packages/core/src/ipc/lockfile.rs).
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


def note(msg):
    """A non-counting informational line (e.g. a skip on an enrolled Mac)."""
    print(f"  NOTE  {msg}")


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


def enclave_key_present(env=None):
    """Whether the presence ladder would reach the HARDWARE rung here - i.e.
    whether a Secure Enclave enrollment key exists. When it does, presence-
    gated commands raise a real Touch ID prompt an automated run cannot
    answer, so callers skip rather than block (repo rule: tests must not raise
    real prompts). The keychain is system-global, so an isolated HOME/XDG does
    not hide it.

    Off macOS there is no Secure Enclave and no hardware rung (the ladder is
    Unavailable by construction), so this is always False there - which is
    what keeps the presence-gated suites running on Linux/Windows CI.

    On macOS it fails SAFE: only a definitive `key: none` line lets the gated
    tests run. A probe error, timeout, non-zero exit, or unrecognized output
    is treated as possibly-enrolled and skips - risking an over-skip (lost
    coverage on a broken probe) is acceptable; risking a real prompt is not.
    Read-only; never prompts."""
    if sys.platform != "darwin":
        return False
    try:
        r = subprocess.run([BIN, "enclave-status"], capture_output=True,
                           text=True, env=env, timeout=10)
    except Exception:
        return True  # indeterminate -> assume enrolled, skip
    if r.returncode != 0:
        return True
    for line in r.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("key:"):
            rest = stripped[len("key:"):].strip()
            # The not-enrolled line is exactly `key:        none (run ...)`.
            # Match on the first whitespace token so a hypothetical value like
            # `nonetheless` is NOT mistaken for `none` (which would fail open).
            first_token = rest.split()[0] if rest.split() else ""
            if first_token == "none":
                return False  # definitively not enrolled -> safe to run
            return True  # present, rejected, or anything else -> skip
    return True  # no key line at all -> indeterminate, skip


def run_with_cli_presence(args, phrase="release", check=True, timeout=15, env=None):
    """Run a capability-restoring CLI subcommand (`unkill`, `pair-client`)
    through its presence floor (ADR-0030/0031). On macOS the presence ladder
    tries the SECURE ENCLAVE signing rung first, but with no enrollment key on
    this machine that rung is Unavailable, so it falls back to the CLI floor:
    the command refuses a non-terminal stdin and then reads the confirmation
    phrase from a terminal. Drive it on a pty and type the phrase. Unix only
    (every caller is Unix-gated).

    Callers MUST guard with `enclave_key_present()` and skip when a key exists:
    the hardware rung raises a real Touch ID sheet the typed phrase cannot
    satisfy, and that path is exercised by the user runbook
    (`just touchid-gates`), not headlessly. Returns a CompletedProcess;
    with check=True a non-zero exit raises."""
    import pty

    master, slave = pty.openpty()
    try:
        p = subprocess.Popen([BIN, *args], stdin=slave,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding="utf-8", env=env)
        os.close(slave)
        slave = -1
        # The pty buffers the phrase until the prompt reads it.
        os.write(master, (phrase + "\n").encode())
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Reap the specific child we spawned; never leave it running.
            p.kill()
            out, err = p.communicate()
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
    result = subprocess.CompletedProcess([BIN, *args], p.returncode, out, err)
    if check and result.returncode != 0:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {err}")
    return result


def unkill_interactive(phrase="release", check=True):
    """Release the kill switch through the CLI's presence floor (ADR-0030).
    See run_with_cli_presence for the headless-vs-hardware nuance."""
    return run_with_cli_presence(["unkill"], phrase=phrase, check=check)


def pair_client_interactive(*args, phrase="release", check=True, env=None):
    """Run `chromium-bridge pair-client ...` through its presence floor
    (ADR-0031): pairing GRANTS harness capability, so it is now gated exactly
    like unkill. See run_with_cli_presence for the headless-vs-hardware
    nuance."""
    return run_with_cli_presence(["pair-client", *args], phrase=phrase,
                                 check=check, env=env)


def nm_read_raw(p):
    hdr = p.stdout.read(4)
    if len(hdr) < 4:
        return None
    (n,) = struct.unpack("<I", hdr)
    return json.loads(p.stdout.read(n))


# The host->extension pushes (ADR-0032 decision 4/7): a policy-capable host now
# emits policy_current and lang_current UNSOLICITED at every connect, and again
# on every policy/language change. A test reading the host's stdout for a reply
# or a tool op must not desynchronize on them, exactly as the real extension
# consumes them at its own gate. nm_read skips them by default; pass
# skip_pushes=False to observe the pushes themselves (test_policy_control_frames
# asserts on them directly).
_HOST_PUSH_TYPES = ("policy_current", "lang_current")


def nm_read(p, skip_pushes=True):
    while True:
        frame = nm_read_raw(p)
        if frame is None:
            return None
        if (skip_pushes and isinstance(frame, dict)
                and frame.get("type") in _HOST_PUSH_TYPES):
            continue
        return frame


# "2026-07-28" here (and "2025-06-18" in initialize below) are hard-coded on
# purpose: this suite is a deliberately independent black-box check of the
# served protocol. The canonical values live in
# src/packages/core/src/protocol.rs; a re-pin there must update these
# literals by hand (the assertions below fail until it does).
MODERN_VERSION = "2026-07-28"
META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
META_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"
# The exact supported set the server advertises (discover's
# supportedVersions and the -32022 error's data.supported). This is rmcp's
# built-in list (ADR-0034 keeps the SDK default so legacy harnesses keep
# negotiating); an rmcp upgrade that moves it fails here AND in the Rust
# version-pin test, and both re-pin by hand.
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18",
                      "2025-11-25", "2026-07-28"]


class McpClient:
    """Minimal MCP JSON-RPC client over stdio to the server subprocess.

    Speaks both eras: discover and the modern_* helpers stamp params with the
    2026-07-28 _meta protocol-version AND client-capabilities keys (rmcp
    requires both on every stateless request); the bare initialize / ping /
    tools_list / call helpers send requests without _meta, which are served
    the legacy era on a connection OPENED by initialize (ADR-0034)."""

    def __init__(self, proc):
        self.proc = proc

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def recv(self):
        return json.loads(self.proc.stdout.readline())

    def modern_params(self, params=None, version=MODERN_VERSION):
        """Return `params` stamped with the modern-era _meta keys (version +
        clientCapabilities; an empty capabilities object is sufficient).
        `version` is overridable (including to non-string values) so the
        version-mismatch tests can send exactly what a broken client would."""
        p = dict(params or {})
        p["_meta"] = {META_VERSION_KEY: version, META_CAPS_KEY: {}}
        return p

    def modern_send(self, method, params=None, _id=1, version=MODERN_VERSION):
        self.send({"jsonrpc": "2.0", "id": _id, "method": method,
                   "params": self.modern_params(params, version)})
        return self.recv()

    def discover(self, _id=1, meta=True, version=MODERN_VERSION):
        """server/discover. meta=False sends the bare probe (no params at
        all); rmcp has no bare-discover form, so the tests use it only to
        pin the refusal/drop actuals (ADR-0034)."""
        if not meta:
            self.send({"jsonrpc": "2.0", "id": _id, "method": "server/discover"})
            return self.recv()
        return self.modern_send("server/discover", _id=_id, version=version)

    def modern_tools_list(self, _id=2, version=MODERN_VERSION):
        return self.modern_send("tools/list", _id=_id, version=version)

    def modern_call(self, name, args, _id=3, version=MODERN_VERSION):
        return self.modern_send("tools/call", {"name": name, "arguments": args},
                                _id=_id, version=version)

    def initialize(self):
        # Legacy-era handshake: no _meta version key, so it lands in the
        # temporary legacy shim (ADR-0034). "2025-06-18" is hard-coded on
        # purpose, like MODERN_VERSION above: an independent black-box pin of
        # the shim's byte-identical behavior.
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


def check_modern_shape(res, label, cache=False, server_meta=False):
    """Assert the modern-era result envelope on `res` (a response's "result"):
    resultType, plus - for the methods that carry them - the ttlMs/cacheScope
    cache fields (server/discover, tools/list) and the serverInfo _meta
    (server/discover ONLY: rmcp stamps the identity on the discover result
    and nothing else, a recorded SHOULD-gap in ADR-0034)."""
    check(res.get("resultType") == "complete", f"{label}: resultType is complete")
    if server_meta:
        si = (res.get("_meta") or {}).get(META_SERVER_INFO_KEY) or {}
        check(si.get("name") == "chromium-bridge",
              f"{label}: _meta serverInfo names chromium-bridge")
        check(bool(re.match(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$",
                            str(si.get("version") or ""))),
              f"{label}: _meta serverInfo version is a semver")
    else:
        check("_meta" not in res, f"{label}: no serverInfo _meta (discover-only)")
    if cache:
        check(res.get("ttlMs") == 3600000, f"{label}: ttlMs is 3600000")
        check(res.get("cacheScope") == "private", f"{label}: cacheScope is private")


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


def test_modern_discover_and_tools():
    print("\n[test] modern discover + tools/list catalogue")
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
        disc = c.discover(_id=1)
        res = disc.get("result") or {}
        # Independent black-box pin of the served versions; the canonical
        # modern pin lives in src/packages/core/src/protocol.rs, the full
        # set is rmcp's (ADR-0034).
        check(res.get("supportedVersions") == SUPPORTED_VERSIONS,
              "discover advertises exactly the rmcp supported set")
        check(res.get("supportedVersions", [None])[-1] == MODERN_VERSION,
              "the newest supported version is 2026-07-28")
        check("tools" in (res.get("capabilities") or {}),
              "capabilities advertises tools")
        check_modern_shape(res, "discover", cache=True, server_meta=True)
        r = c.modern_tools_list(_id=2)
        tres = r.get("result") or {}
        check_modern_shape(tres, "tools/list", cache=True)
        tools = tres.get("tools") or []
        names = [t.get("name") for t in tools]
        check("tab_list" in names, "tools/list includes tab_list")
        check("page_eval" in names, "tools/list includes page_eval")
        check("page_snapshot_precise" in names, "tools/list includes page_snapshot_precise")
        # page_eval description must carry a HIGH RISK warning
        ev = next((t for t in tools if t.get("name") == "page_eval"),
                  {"description": "", "inputSchema": {}})
        check("HIGH RISK" in ev["description"], "page_eval description warns HIGH RISK")
        check(ev["inputSchema"].get("required") == ["code"], "page_eval requires code arg")
        # precise snapshot description must warn about the debugger banner
        ps = next((t for t in tools if t.get("name") == "page_snapshot_precise"),
                  {"description": ""})
        check("debugger" in ps["description"].lower(),
              "page_snapshot_precise description mentions debugger")
        check("cookie_get" in names, "tools/list includes cookie_get")
        check("storage_get" in names, "tools/list includes storage_get")
        # cookie_get description must mention httpOnly + read-only
        ck = next((t for t in tools if t.get("name") == "cookie_get"),
                  {"description": ""})
        check("httpOnly" in ck["description"], "cookie_get description mentions httpOnly")
        check("masked" in ck["description"].lower(), "cookie_get description mentions masking")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_modern_discover_is_stateless():
    """Statelessness pin: server/discover carrying its own _meta is served as
    the FIRST request on a fresh connection - no initialize, no prior traffic
    of any kind. The bare probe (no _meta at all) has no served form in rmcp:
    post-open it is refused with -32602 (ADR-0034 cut the planned leniency)."""
    print("\n[test] modern discover: stateless first request; no bare-probe form")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        r = c.discover(_id=1)
        check(r.get("error") is None, "discover as the very first request is served")
        res = r.get("result") or {}
        check_modern_shape(res, "discover", cache=True, server_meta=True)
        check(res.get("supportedVersions") == SUPPORTED_VERSIONS,
              "supportedVersions is exactly the rmcp supported set")
        check(isinstance((res.get("capabilities") or {}).get("tools"), dict),
              "capabilities advertises tools as an object")
        check(res != {} and "instructions" not in res,
              "discover carries no instructions field")
        check(set(res) >= {"resultType", "supportedVersions", "capabilities",
                           "ttlMs", "cacheScope", "_meta"},
              "discover result carries all the pinned keys")
        # The bare probe is NOT served: a params-less request cannot satisfy
        # the stateless metadata requirement, so it is refused as invalid
        # params - never silently answered, never legacy-routed (the
        # connection was opened statelessly).
        bare = c.discover(_id=2, meta=False)
        check((bare.get("error") or {}).get("code") == -32602,
              "the bare probe (no _meta) is refused with -32602")
        # A modern-era notification (no id) never gets a reply: the next
        # frame on the wire belongs to the next request.
        c.send({"jsonrpc": "2.0", "method": "notifications/initialized",
                "params": c.modern_params()})
        r3 = c.discover(_id=3)
        check(r3.get("id") == 3 and r3.get("result") == res,
              "a modern notification is swallowed; the next reply is the next request's")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def read_reply_or_eof(proc, timeout=10):
    """One guarded readline on `proc`'s stdout: the line ("" on EOF), None on
    timeout, or an error marker on a read exception - each distinct, so an
    EOF assertion can never pass by accident. The drop tests must never hang
    CI on a regression that leaves the connection open but silent; the
    caller's cleanup kills the process, which also unblocks the parked
    reader thread."""
    box = {}

    def _read():
        try:
            box["line"] = proc.stdout.readline()
        except (ValueError, OSError) as e:
            box["line"] = f"<readline error: {e!r}>"

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(timeout)
    return box.get("line")


def test_invalid_opener_drops_the_connection():
    """The opener rule, pinned as the contract (ADR-0034): a connection's
    FIRST request must be a legacy initialize or a well-formed stateless
    request (_meta with a string protocolVersion AND clientCapabilities).
    Anything else - a bare server/discover probe included - fails the rmcp
    opener: the connection drops without a reply and the stdio server exits.
    Fail closed, never serve a peer whose era cannot be established. (A bare
    ping is the one pre-open exception: the spec allows ping at any time,
    but answering it does NOT open the connection.)"""
    print("\n[test] invalid opener: bare first request -> connection dropped")
    for first, label in [
        ({"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
         "bare server/discover"),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
         "bare tools/list"),
        ({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
          "params": {"_meta": {META_VERSION_KEY: MODERN_VERSION}}},
         "_meta missing clientCapabilities"),
    ]:
        try:
            os.remove(LOCK)
        except FileNotFoundError:
            pass
        mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8")
        try:
            wait_lock(mcp)
            c = McpClient(mcp)
            c.send(first)
            line = read_reply_or_eof(mcp)
            check(line == "", f"{label} as the first request gets no reply (EOF)")
            try:
                mcp.wait(timeout=5)
                exited = True
            except subprocess.TimeoutExpired:
                exited = False
            check(exited, f"{label}: the server closed the connection (fail closed)")
        finally:
            if mcp.poll() is None:
                mcp.kill()
            try:
                mcp.stdin.close()
            except Exception:
                pass
            mcp.wait(timeout=3)
    # The ping exception: answered pre-open, but NOT an opener - the next
    # bare request still fails the opener and drops the connection.
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        r = c.ping(_id=1)
        check(r.get("id") == 1 and r.get("result") == {},
              "a bare ping before any opener is answered {}")
        c.send({"jsonrpc": "2.0", "id": 2, "method": "server/discover"})
        line = read_reply_or_eof(mcp)
        check(line == "", "ping does not open the connection: the next bare "
              "request still drops it")
    finally:
        if mcp.poll() is None:
            mcp.kill()
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_modern_tools_list_cache_and_order():
    print("\n[test] modern tools/list: cache fields + deterministic order")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    mcp2 = None
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        r1 = c.modern_tools_list(_id=1)
        r2 = c.modern_tools_list(_id=2)
        res1 = r1.get("result") or {}
        res2 = r2.get("result") or {}
        check_modern_shape(res1, "tools/list", cache=True)
        tools = res1.get("tools") or []
        check(all(t.get("name") and t.get("description") and t.get("inputSchema")
                  for t in tools) and bool(tools),
              "every tool carries name/description/inputSchema")
        names1 = [t.get("name") for t in tools]
        names2 = [t.get("name") for t in res2.get("tools") or []]
        check(bool(names1) and names1 == names2,
              "tool order is identical across two consecutive calls")
        # Determinism must hold across processes too, not just within one
        # process's startup ordering: a fresh server lists the same order.
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=5)
        try:
            os.remove(LOCK)
        except FileNotFoundError:
            pass
        mcp2 = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8")
        wait_lock(mcp2)
        r3 = McpClient(mcp2).modern_tools_list(_id=3)
        names3 = [t.get("name") for t in (r3.get("result") or {}).get("tools") or []]
        check(bool(names1) and names1 == names3,
              "tool order is identical across a server restart")
    finally:
        for p in (mcp, mcp2):
            if p is None:
                continue
            try:
                p.stdin.close()
            except Exception:
                pass
            try:
                p.wait(timeout=3)
            except Exception:
                # A server that ignores stdin EOF is a regression, but the
                # suite must not leak it past this test: reap it hard.
                p.kill()
                try:
                    p.wait(timeout=3)
                except Exception:
                    pass


def test_modern_version_mismatch_is_per_request():
    """A wrong STRING _meta protocol version gets the typed -32022 error with
    its data payload; a NON-STRING version is malformed metadata and gets
    -32602 (invalid params) naming the field. Both are per-request: the SAME
    connection serves a correct request right after."""
    print("\n[test] modern era: version mismatch -> -32022/-32602, connection survives")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        r = c.modern_tools_list(_id=51, version="2099-01-01")
        err = r.get("error") or {}
        check(r.get("id") == 51 and err.get("code") == -32022,
              "wrong version -> error -32022 on the request's own id")
        check((err.get("data") or {}).get("supported") == SUPPORTED_VERSIONS,
              "error data lists the full supported set")
        check((err.get("data") or {}).get("requested") == "2099-01-01",
              "error data echoes the requested version")
        # A non-string version cannot be read as a version claim at all, so
        # it is refused as malformed metadata (-32602 naming the field),
        # not as an unsupported version.
        r = c.modern_tools_list(_id=52, version=42)
        err = r.get("error") or {}
        check(r.get("id") == 52 and err.get("code") == -32602,
              "non-string version -> error -32602 on the request's own id")
        check(META_VERSION_KEY in str(err.get("message", "")),
              "the -32602 message names the malformed _meta field")
        # The mismatch rule is per-request and method-blind: server/discover
        # with a WRONG version is a mismatch too.
        r = c.discover(_id=53, version="2099-01-01")
        check(r.get("id") == 53 and (r.get("error") or {}).get("code") == -32022,
              "discover with a wrong version -> error -32022")
        r = c.modern_tools_list(_id=54)
        res = r.get("result") or {}
        check(r.get("id") == 54 and res.get("resultType") == "complete"
              and bool(res.get("tools")),
              "the same connection still serves a correct modern request")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_initialize_is_served_in_every_era():
    """rmcp serves initialize at ANY point, modern _meta or not: it is the
    legacy negotiation, and the era is a per-request property. The original
    design intended a modern-era initialize to be refused with an error
    naming 2026-07-28; the SDK's actual (recorded in ADR-0034) is to answer
    it as a negotiation, echoing a supported requested revision. This pin
    keeps that deviation visible."""
    print("\n[test] initialize is served in every era (rmcp negotiation)")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        r = c.modern_send("initialize",
                          {"protocolVersion": MODERN_VERSION, "capabilities": {},
                           "clientInfo": {"name": "e2e", "version": "0.1"}},
                          _id=61)
        res = r.get("result") or {}
        check(r.get("id") == 61 and r.get("error") is None,
              "initialize with modern _meta is served, not refused")
        check(res.get("protocolVersion") == MODERN_VERSION,
              "the negotiation echoes the supported requested revision")
        check(all(k not in res for k in ("resultType", "ttlMs", "cacheScope")),
              "the initialize result keeps the legacy shape")
        # An initialize requesting an UNKNOWN revision is answered with the
        # newest supported one instead of an error (rmcp's fallback).
        c.send({"jsonrpc": "2.0", "id": 62, "method": "initialize",
                "params": {"protocolVersion": "1999-01-01", "capabilities": {},
                           "clientInfo": {"name": "e2e", "version": "0.1"}}})
        r = c.recv()
        check((r.get("result") or {}).get("protocolVersion") == MODERN_VERSION,
              "an unknown requested revision falls back to the newest supported")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_modern_tools_call_round_trip():
    print("\n[test] modern tools/call round-trip via real native host")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    nh = None
    try:
        lf = wait_lock(mcp)
        check(lf is not None, "lock file written")

        def responder(req):
            assert req["op"] == "tab_list", f"unexpected op {req['op']}"
            return {"id": req["id"], "ok": True,
                    "data": [{"id": 7, "title": "Modern E2E Tab", "url": "https://x",
                              "active": True}]}

        nh = start_bridge_host()
        c = McpClient(mcp)
        wait_host_ready(nh)  # let the host connect, attest, and complete the handshake
        # serve the single tab_list request the call below will trigger
        served = []
        t = threading.Thread(target=lambda: served.append(serve_bridge_req(nh, responder)))
        t.start()

        # The modern era has no handshake: the tools/call is the connection's
        # first request.
        r = c.modern_call("tab_list", {}, _id=5)
        t.join(timeout=3)
        check(bool(served), "native host received the modern tools/call BridgeReq")
        res = r.get("result") or {}
        text = (res.get("content") or [{}])[0].get("text")
        try:
            data = json.loads(text) if text else []
        except ValueError:
            data = []  # non-JSON content (e.g. an error string) -> FAIL below
        check(r.get("id") == 5 and bool(data)
              and data[0].get("title") == "Modern E2E Tab",
              "modern tools/call result carries host data")
        check(res.get("isError") is False, "modern tools/call isError=false")
        check_modern_shape(res, "tools/call")
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
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


# --- shim-era tests: delete when legacy-era support is dropped (ADR-0034) ---
# On a connection OPENED by initialize, requests without the _meta
# protocol-version key are served in the legacy era, which must stay
# byte-identical to the pre-migration protocol until that support is
# removed. These tests pin that byte-identity. (The rest of the suite still
# uses the bare initialize/call helpers as session plumbing; when legacy-era
# support goes, that plumbing moves to the modern_* helpers in the same
# change.)


def test_legacy_shim_handshake():
    print("\n[test] legacy shim: initialize + ping keep the exact legacy shapes")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        init = c.initialize()
        res = init.get("result") or {}
        check(res.get("protocolVersion") == "2025-06-18",
              "legacy initialize returns protocolVersion 2025-06-18")
        check("tools" in (res.get("capabilities") or {}),
              "legacy capabilities advertises tools")
        check("serverInfo" in res, "legacy initialize carries serverInfo")
        check(all(k not in res for k in ("resultType", "ttlMs", "cacheScope", "_meta")),
              "legacy initialize has none of the modern keys")
        # notifications/initialized is swallowed: the next reply on the wire
        # must be the ping's (matching id), not a stray notification response.
        c.initialized()
        ping = c.ping(_id=5)
        check(ping.get("id") == 5 and ping.get("result") == {},
              "initialized is swallowed; ping returns exactly {}")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_legacy_shim_tools_list_shape():
    print("\n[test] legacy shim: tools/list has no modern cache/meta fields")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        r = c.tools_list()
        res = r.get("result") or {}
        check(bool(res.get("tools")), "legacy tools/list still lists tools")
        for key in ("resultType", "ttlMs", "cacheScope", "_meta"):
            check(key not in res, f"legacy tools/list has no {key}")
        # The era discriminator is the version KEY, not _meta presence: a
        # request whose _meta lacks the version key (e.g. only a
        # progressToken) still lands in the shim.
        c.send({"jsonrpc": "2.0", "id": 6, "method": "tools/list",
                "params": {"_meta": {"io.modelcontextprotocol/progressToken": "t1"}}})
        r = c.recv()
        res = r.get("result") or {}
        check(r.get("id") == 6 and bool(res.get("tools"))
              and all(k not in res for k in ("resultType", "ttlMs", "cacheScope", "_meta")),
              "_meta WITHOUT the version key still lands in the legacy shim")
    finally:
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=3)


def test_mixed_era_interleaving():
    """The era is a per-request property (the _meta version key), never
    connection state: one connection serves both eras request-by-request,
    each response in its own era's exact shape."""
    print("\n[test] mixed-era interleaving on one connection")
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        init = c.initialize()
        ires = init.get("result") or {}
        check(ires.get("protocolVersion") == "2025-06-18",
              "legacy initialize keeps the legacy version")
        check(all(k not in ires for k in ("resultType", "_meta")),
              "legacy initialize has no modern keys")
        disc = c.discover(_id=42)
        dres = disc.get("result") or {}
        check(disc.get("id") == 42 and dres.get("supportedVersions") == SUPPORTED_VERSIONS,
              "modern discover works after a legacy initialize")
        check(dres.get("resultType") == "complete",
              "modern discover keeps its modern shape")
        ping = c.ping(_id=43)
        check(ping.get("id") == 43 and ping.get("result") == {},
              "legacy ping still returns exactly {} after modern traffic")
        mt = c.modern_tools_list(_id=44)
        mres = mt.get("result") or {}
        check(mt.get("id") == 44 and mres.get("resultType") == "complete"
              and mres.get("ttlMs") == 3600000
              and mres.get("cacheScope") == "private"
              and "_meta" not in mres,
              "modern tools/list keeps its modern shape mid-interleave "
              "(no serverInfo _meta: discover-only)")
        lt = c.tools_list(_id=45)
        lres = lt.get("result") or {}
        check(lt.get("id") == 45 and bool(lres.get("tools")),
              "legacy tools/list still lists tools")
        check(all(k not in lres for k in ("resultType", "ttlMs", "cacheScope", "_meta")),
              "legacy tools/list has none of the modern keys")
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
    if enclave_key_present():
        note("admin-frames test skipped: an Enclave key is enrolled, so "
             "pair-client would raise a real Touch ID prompt this automated "
             "run cannot answer. The hardware pairing path is covered by "
             "`just touchid-gates`.")
        return
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
        # trusted client the admin frames will enumerate and revoke. Pairing
        # is presence-gated (ADR-0031); run_with_cli_presence drives the CLI
        # floor on a pty.
        pair_client_interactive("--name", "pytest", "--this-parent", env=env)
        pair_client_interactive("--name", "codex", "--hash", "aa" * 32, env=env)
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


def test_policy_control_frames():
    """Phase 2 of ADR-0032: the native host PUSHES policy_current and
    lang_current unsolicited at connect (decision 4/7's never-speak-first
    identification), ANSWERS the four extension-originated frames (policy_get
    -> policy_current, lang_get/lang_set -> lang_current, legacy_settings ->
    recorded pending, no reply), and still DROPS the host->extension pushes
    when they arrive from the browser leg. Uses an isolated runtime dir; no
    pairing and no presence-gated path is involved (policy_get answers ok:false
    on the empty store, and the language lane never prompts), so this runs even
    on an enrolled Mac. The symmetric server-leg drop is unit-pinned in
    native_host.rs (server_injected_policy_frames_are_dropped_not_forwarded)."""
    print("\n[test] policy/language frames: connect push + answer round-trip (ADR-0032 phase 2)")
    rundir = tempfile.mkdtemp(prefix="bb-policy-e2e-")
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
        mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8",
                               env=env)
        wait_lock(mcp)
        nh = start_bridge_host(env=env)
        wait_host_ready(nh)

        # Connect push (decision 4/7): the host identifies itself unsolicited
        # with policy_current then lang_current, in that order. The store is
        # empty in this isolated dir, so policy_current fails closed (ok:false,
        # no baseline) and language reads its default (en, seq 0).
        push = nm_read_raw(nh)
        check(push is not None and push.get("type") == "policy_current"
              and push.get("ok") is False and "baseline" not in push,
              "the host pushes policy_current at connect (ok:false on an empty store)")
        push = nm_read_raw(nh)
        check(push is not None and push.get("type") == "lang_current"
              and push.get("value") == "en" and push.get("seq") == 0,
              "the host pushes lang_current at connect (the default en, seq 0)")

        # legacy_settings is fire-and-forget (Phase 4 records the pending
        # import): no reply. Prove it by driving a real tool op right after -
        # the first non-push frame must be the tool op, never a stray reply.
        nm_write(nh, {"type": "legacy_settings", "bag": {"groupTabs": True}})
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        c.send({"jsonrpc": "2.0", "id": 91, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        frame = nm_read(nh)  # skips any connect/tick pushes
        check(frame is not None and frame.get("op") == "tab_list",
              "legacy_settings is answered with no reply (first frame is the tool op)")
        nm_write(nh, {"id": frame["id"], "ok": True,
                      "data": [{"id": 1, "title": "After Policy", "url": "u",
                                "active": True}]})
        r = c.recv()
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "After Policy",
              "round trip completes; legacy_settings was neither forwarded nor answered")

        # policy_get -> policy_current, answered by the host. ok:false on the
        # empty store (fail closed), never a silent default.
        nm_write(nh, {"type": "policy_get"})
        reply = nm_read_raw(nh)
        check(reply is not None and reply.get("type") == "policy_current"
              and reply.get("ok") is False,
              "policy_get is answered with policy_current (ok:false on the empty store)")

        # lang_set applies the value and bumps the sequence; the reply is the
        # new lang_current, and lang_get reflects it.
        nm_write(nh, {"type": "lang_set", "value": "zh_CN"})
        reply = nm_read_raw(nh)
        # A change bumps the epoch too, so a duplicate lang_current push may
        # trail on the watch tick; read for the reply among any pushes.
        while reply is not None and not (reply.get("type") == "lang_current"):
            reply = nm_read_raw(nh)
        check(reply is not None and reply.get("value") == "zh_CN"
              and reply.get("seq") == 1,
              "lang_set applies the value and bumps the sequence to 1")
        nm_write(nh, {"type": "lang_get"})
        # Read lang_current replies until the value settles on zh_CN (a
        # trailing epoch-bump push carries the same value+seq, so any is fine).
        reply = nm_read_raw(nh)
        while reply is not None and reply.get("type") != "lang_current":
            reply = nm_read_raw(nh)
        check(reply is not None and reply.get("value") == "zh_CN"
              and reply.get("seq") == 1,
              "lang_get reflects the applied language (zh_CN, seq 1)")

        # Host-direction pushes arriving FROM the browser leg (a compromised
        # extension bouncing state back) are DROPPED, never forwarded to the
        # MCP server: the pump still forwards ordinary traffic after them.
        nm_write(nh, {"type": "policy_current", "ok": True,
                      "baseline": "YmFzZQ==", "sig": "c2ln"})
        nm_write(nh, {"type": "lang_current", "value": "en", "seq": 99})
        c.send({"jsonrpc": "2.0", "id": 92, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        frame = nm_read(nh)
        check(frame is not None and frame.get("op") == "tab_list",
              "pump still forwards ordinary frames after injected host-direction pushes")
        nm_write(nh, {"id": frame["id"], "ok": True,
                      "data": [{"id": 1, "title": "After Injected", "url": "u",
                                "active": True}]})
        r = c.recv()
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "After Injected",
              "round trip completes; injected policy_current/lang_current were dropped")
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


def test_kill_switch_round_trip():
    """ADR-0030/0032: `kill` halts everything (typed BRIDGE_KILLED errors on a
    LIVE broker, severed browser leg, control-plane-only hosts); the extension's
    `kill_release` frame is now REFUSED (ADR-0032 decision 6: release is app/CLI
    only), release goes through `chromium-bridge unkill`, and the bridge fully
    recovers. Also proves the audit trail: the kill, the refused extension
    release, and the CLI release land in the 0600 audit file and
    `chromium-bridge audit` renders them."""
    print("\n[test] global kill switch: engage, refuse, release, recover (ADR-0030)")
    if enclave_key_present():
        note("kill-switch round-trip skipped: an Enclave key is enrolled, so "
             "the CLI `unkill` used to release here would raise a real Touch ID "
             "prompt this automated run cannot answer. The hardware unkill path "
             "is covered by `just touchid-gates`.")
        return
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass
    rundir = os.path.dirname(os.path.dirname(LOCK))
    mcp = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, encoding="utf-8")
    nh = None
    nh2 = None
    nh3 = None
    try:
        wait_lock(mcp)
        c = McpClient(mcp)
        c.initialize()
        c.initialized()
        nh = start_bridge_host()
        wait_host_ready(nh)

        # Healthy round trip before the kill.
        served = []
        t = threading.Thread(target=lambda: served.append(
            serve_bridge_req(nh, lambda req: {"id": req["id"], "ok": True, "data": []})))
        t.start()
        r = c.call("tab_list", {}, _id=80)
        t.join(timeout=5)
        check(not r["result"].get("isError", False), "bridge works before the kill")

        # Engage from the CLI surface.
        kill = subprocess.run([BIN, "kill"], capture_output=True, text=True)
        check(kill.returncode == 0, "`kill` exits 0")

        # The LIVE broker refuses the very next call with the stable typed
        # code -- and the harness connection survives to deliver it (a typed
        # refusal, not an opaque EOF).
        r = c.call("tab_list", {}, _id=81)
        text = r["result"]["content"][0]["text"]
        check(r["result"].get("isError") is True and "BRIDGE_KILLED" in text,
              "a live broker answers tools/call with the typed BRIDGE_KILLED error")

        # The connected browser leg is severed within a watcher tick: the
        # host sees its socket close and exits (it may first relay the
        # transition push toward "Chrome"; both frames-then-EOF and plain EOF
        # are valid shapes).
        try:
            nh.wait(timeout=8)
        except Exception:
            pass
        # Keep the handle either way: the finally block only kills a host
        # that is still running, so a failed exit is cleaned up, not leaked.
        check(nh.poll() is not None, "the connected native host exits after the kill")

        # A freshly spawned host must NOT bridge: it comes up control-plane
        # only, announces the killed state (startup push), answers a status
        # query, and REFUSES the extension's retired release frame (ADR-0032
        # decision 6: release is app/CLI only now).
        nh2 = start_bridge_host()
        frame = nm_read(nh2)
        check(frame is not None and frame.get("type") == "kill_status_result"
              and frame.get("ok") is True and frame.get("killed") is True,
              "a fresh host announces the killed state (control-plane mode)")
        check(not nh2.ready.is_set(),
              "the control-plane host never completes a bridge handshake")
        nm_write(nh2, {"type": "kill_status"})
        frame = nm_read(nh2)
        check(frame is not None and frame.get("type") == "kill_status_result"
              and frame.get("killed") is True, "kill_status is answered locally")
        # The extension release path is retired: the host refuses it (ok:false,
        # no killed claim) and the switch stays engaged.
        nm_write(nh2, {"type": "kill_release"})
        frame = nm_read(nh2)
        check(frame is not None and frame.get("type") == "kill_status_result"
              and frame.get("ok") is False and frame.get("killed") is None,
              "the extension kill_release is refused (ADR-0032 decision 6)")
        nm_write(nh2, {"type": "kill_status"})
        frame = nm_read(nh2)
        check(frame is not None and frame.get("killed") is True,
              "the refused release left the switch engaged")

        # Release now goes through the CLI (`chromium-bridge unkill`) behind the
        # ADR-0031 presence gate - here the CLI floor on a pty. The
        # control-plane host observes the release and exits so the extension
        # reconnects into a bridge-mode host.
        unkill_interactive()
        # Drain any trailing transition push until EOF, bounded so a host that
        # wrongly stays up fails the test instead of hanging the suite.
        drained = []
        drain = threading.Thread(target=lambda: [
            drained.append(f) for f in iter(lambda: nm_read(nh2), None)])
        drain.start()
        drain.join(timeout=8)
        try:
            nh2.wait(timeout=8)
        except Exception:
            pass
        # Keep the handle either way: the finally block only kills a host
        # that is still running, so a failed exit is cleaned up, not leaked.
        check(nh2.poll() is not None, "the control-plane host exits after the release")

        # Full recovery on the SAME broker: a new host attaches and the
        # harness's calls flow again.
        nh3 = start_bridge_host()
        wait_host_ready(nh3)
        served = []
        t = threading.Thread(target=lambda: served.append(
            serve_bridge_req(nh3, lambda req: {"id": req["id"], "ok": True, "data": []})))
        t.start()
        r = c.call("tab_list", {}, _id=82)
        t.join(timeout=5)
        check(not r["result"].get("isError", False),
              "the bridge fully recovers after the release")

        # The audit trail: 0600 on-disk file carrying the kill and the
        # release, rendered by the read-only subcommand. Read the rotated
        # file too, exactly like the CLI reader, so a rotation mid-suite
        # cannot fake a missing record.
        audit_path = os.path.join(rundir, "chromium-bridge", "audit.log")
        check(os.path.exists(audit_path), "audit.log exists in the runtime dir")
        if os.name != "nt" and os.path.exists(audit_path):
            mode = os.stat(audit_path).st_mode & 0o777
            check(mode == 0o600, f"audit.log is 0600 (got {oct(mode)})")
        records = []
        for name in (audit_path + ".1", audit_path):
            try:
                with open(name) as f:
                    for line in f:
                        records.append(json.loads(line))
            except FileNotFoundError:
                pass
        kinds = [rec.get("kind") for rec in records]
        check("kill_engage" in kinds, "the kill is in the audit file")
        check("kill_release" in kinds, "the release is in the audit file")
        releases = [rec for rec in records if rec.get("kind") == "kill_release"]
        # The extension's retired release attempt is audited as a refusal
        # (ADR-0032 decision 6): surface=extension, outcome=refused, no auth.
        check(any(r.get("surface") == "extension" and r.get("outcome") == "refused"
                  for r in releases),
              "the extension kill_release is audited as a refusal (ADR-0032 decision 6)")
        # The CLI release names the presence rung that authorized it (ADR-0031).
        # On a machine WITHOUT a Secure Enclave key the CLI floor is used
        # (auth=cli_confirm); on an enrolled Mac the hardware rung runs and the
        # release requires a real Touch ID tap (auth=touch_id) - but this test
        # is skipped on an enrolled Mac above, so cli_confirm is the live path.
        cli_release = next((r for r in releases if r.get("surface") == "cli"), None)
        check(cli_release is not None and cli_release.get("outcome") == "ok",
              "the CLI unkill release is audited (surface=cli, ok)")
        detail = cli_release.get("detail", "") if cli_release else ""
        check("auth=cli_confirm" in detail or "auth=touch_id" in detail,
              "the CLI release names the presence rung that authorized it")
        killed_calls = [rec for rec in records
                        if rec.get("kind") == "tool_call"
                        and rec.get("code") == "BRIDGE_KILLED"]
        check(bool(killed_calls), "the refused tool call is audited with its code")
        shown = subprocess.run([BIN, "audit"], capture_output=True, text=True)
        check(shown.returncode == 0 and "kill_engage" in shown.stdout
              and "kill_release" in shown.stdout,
              "`audit` renders the trail read-only")
    finally:
        for host in (nh, nh2, nh3):
            if host is not None and host.poll() is None:
                host.kill()
                try:
                    host.wait(timeout=3)
                except Exception:
                    pass
        try:
            mcp.stdin.close()
        except Exception:
            pass
        mcp.wait(timeout=5)
        # Leave the isolated dir clean for the tests that follow: the kill
        # state and the audit trail are this test's artifacts.
        for name in ("revocation.json", "audit.log", "audit.log.1", "audit.log.lock"):
            try:
                os.remove(os.path.join(rundir, "chromium-bridge", name))
            except FileNotFoundError:
                pass


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
        # The same rule holds in the modern era (unknown method WITH the
        # _meta version key).
        r = c.modern_send("resources/list", _id=12)
        check(r.get("id") == 12 and (r.get("error") or {}).get("code") == -32601,
              "modern-era unknown method -> error code -32601")
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
        # mismatch to stderr. communicate() drains and closes stdin itself,
        # which ends the server so we can read that log. Do NOT close stdin
        # first: on Python 3.12 communicate() flushes the stdin object
        # unconditionally and a manually pre-closed one raises ValueError
        # (3.13+ tolerates it).
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
    test_modern_discover_and_tools()
    test_modern_discover_is_stateless()
    test_invalid_opener_drops_the_connection()
    test_modern_tools_list_cache_and_order()
    test_modern_version_mismatch_is_per_request()
    test_initialize_is_served_in_every_era()
    test_modern_tools_call_round_trip()
    # shim-era tests: delete when legacy-era support is dropped (ADR-0034)
    test_legacy_shim_handshake()
    test_legacy_shim_tools_list_shape()
    test_mixed_era_interleaving()
    test_tab_list_round_trip()
    test_page_eval_round_trip()
    test_page_snapshot_precise_round_trip()
    test_cookie_get_round_trip()
    test_storage_get_round_trip()
    test_native_host_mode()
    test_enclave_control_frames()
    test_admin_control_frames()
    test_policy_control_frames()
    test_kill_switch_round_trip()
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
