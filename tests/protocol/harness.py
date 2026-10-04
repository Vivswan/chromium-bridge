"""Shared harness for the protocol suites (e2e, adversarial, chaos).

The suites drive the real release binary as subprocesses and speak its wire
protocols from the outside: Native-Messaging frames to a `--native-host`, MCP
JSON-RPC over the server's stdio, raw connects to the bridge socket. This
module holds what they share: runtime-dir isolation, the process spawners, the
wire helpers, the whole-reply expectations, and the TestCase base that reaps
every process a test started.

Safety rule: every binary spawned here runs inside a private, per-run runtime
dir (`isolate`), so the lock, socket, pairing state, and broker logic can
never reach the developer's real bridge. The spawners refuse to run before
isolation has taken, and the dir is removed at interpreter exit on every path.

Stdlib only, on purpose: an independent implementation of the protocols with
no dependencies is what makes these suites catch framing and encoding bugs the
Rust types cannot see. Never add a package.
"""
import atexit
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
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(REPO, "target", "release",
                   "chromium-bridge" + (".exe" if os.name == "nt" else ""))

# Set by isolate(); every spawner re-checks them through require_isolated().
RUNDIR = None
LOCK = None
# Every runtime dir this process created; a child may only be pointed at one of these.
OWNED_RUNTIME_DIRS = set()


def within(child, parent):
    """True when `child` resolves inside `parent`. realpath + commonpath, so a
    symlinked temp root (/var -> /private/var on macOS) and a lexical cousin
    (/tmp/bb vs /tmp/bb-evil) are both handled."""
    try:
        p = os.path.realpath(parent)
        return os.path.commonpath([os.path.realpath(child), p]) == p
    except ValueError:
        return False


def lock_path(rundir):
    # Mirrors LockFile::path() in src/packages/core/src/ipc/lockfile.rs.
    return os.path.join(rundir, "chromium-bridge", "run.lock")


def new_runtime_dir(prefix):
    """A fresh private runtime dir directly under the OS temp dir (a nested
    one overruns the Unix socket path limit), removed at interpreter exit
    whether the suite passes, fails, or dies on an exception."""
    rundir = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, rundir, ignore_errors=True)
    OWNED_RUNTIME_DIRS.add(rundir)
    return rundir


def isolate(prefix):
    """Point every future subprocess at a fresh private runtime dir and prove
    it took; refuse to run otherwise."""
    global RUNDIR, LOCK
    rundir = new_runtime_dir(prefix)
    os.environ["XDG_RUNTIME_DIR"] = rundir
    os.environ["XDG_CONFIG_HOME"] = os.path.join(rundir, "config")
    if sys.platform == "darwin":
        os.environ["HOME"] = rundir
    lock = lock_path(rundir)
    if not (os.path.isdir(rundir) and within(rundir, tempfile.gettempdir())):
        sys.exit("REFUSING TO RUN: isolation dir is not a fresh temp dir")
    if os.environ.get("XDG_RUNTIME_DIR") != rundir:
        sys.exit("REFUSING TO RUN: XDG_RUNTIME_DIR is not the isolation dir")
    if not within(lock, rundir):
        sys.exit("REFUSING TO RUN: lock path escaped the isolation dir")
    RUNDIR, LOCK = rundir, lock
    print(f"[isolation] per-run runtime dir: {rundir}", file=sys.stderr)
    print(f"[isolation] lock path:           {lock}", file=sys.stderr)
    return rundir


def require_isolated(env=None):
    """The runtime dir a child would see (`env`, else this process's) is one
    this harness created, and LOCK points inside it."""
    runtime = (os.environ if env is None else env).get("XDG_RUNTIME_DIR")
    if not (runtime in OWNED_RUNTIME_DIRS and within(LOCK, runtime)):
        raise RuntimeError("REFUSING TO SPAWN: runtime-dir isolation precondition not met")


def ensure_binary():
    if os.path.exists(BIN):
        return
    print("[setup] release binary missing, building...", file=sys.stderr)
    subprocess.check_call(["cargo", "build", "--release", "--manifest-path",
                           os.path.join(REPO, "Cargo.toml")])


def remove_lock(env=None):
    require_isolated(env)
    try:
        os.remove(LOCK)
    except FileNotFoundError:
        pass


def wait_lock(proc=None, timeout=8):
    """The lock file's contents once it exists, or None after `timeout`. With
    `proc`, only a lock naming that pid counts: a stale lock from a previous
    test's server still exiting would otherwise point at a dead port."""
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


# ---------------------------------------------------------------------------
# Native-Messaging frames (extension <-> host)
# ---------------------------------------------------------------------------

def nm_write(p, obj):
    data = json.dumps(obj).encode()
    p.stdin.write(struct.pack("<I", len(data)) + data)
    p.stdin.flush()


def nm_read_raw(p):
    hdr = p.stdout.read(4)
    if len(hdr) < 4:
        return None
    (n,) = struct.unpack("<I", hdr)
    return json.loads(p.stdout.read(n))


# The host pushes policy_current and lang_current unsolicited at every connect
# and on every change; a reader waiting for a reply or a tool op skips them,
# as the real extension does at its own gate.
HOST_PUSH_TYPES = ("policy_current", "lang_current")


def nm_read(p, skip_pushes=True):
    while True:
        frame = nm_read_raw(p)
        if frame is None:
            return None
        if (skip_pushes and isinstance(frame, dict)
                and frame.get("type") in HOST_PUSH_TYPES):
            continue
        return frame


def nm_read_type(p, frame_type):
    """The next frame of `frame_type`, skipping every other frame (a change
    bumps the epoch, so a duplicate push may trail the reply it accompanies)."""
    while True:
        frame = nm_read_raw(p)
        if frame is None or frame.get("type") == frame_type:
            return frame


# ---------------------------------------------------------------------------
# MCP JSON-RPC over stdio (harness <-> server)
# ---------------------------------------------------------------------------

# Hard-coded on purpose: the suites are an independent black-box pin of the
# served protocol. The canonical values live in src/packages/core/src/protocol.rs
# and rmcp; a re-pin there updates these literals by hand.
MODERN_VERSION = "2026-07-28"
# The newest revision with an initialize handshake: rmcp answers a modern or
# unknown requested revision with this one.
NEWEST_LEGACY_VERSION = "2025-11-25"
LEGACY_VERSION = "2025-06-18"
META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
META_CAPS_KEY = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18",
                      "2025-11-25", "2026-07-28"]
CACHE_FIELDS = {"ttlMs": 3600000, "cacheScope": "private"}
SERVER_INFO = {"name": "chromium-bridge", "version": "<semver>"}
# The whole server/discover result, after normalized().
DISCOVER_RESULT = {
    "resultType": "complete",
    "supportedVersions": SUPPORTED_VERSIONS,
    "capabilities": {"tools": {}},
    "_meta": {META_SERVER_INFO_KEY: SERVER_INFO},
    **CACHE_FIELDS,
}
# The whole modern tools/list result once its `tools` array is taken out.
TOOLS_LIST_ENVELOPE = {"resultType": "complete", **CACHE_FIELDS}
# The whole catalogue a client sees, in the served order: tools_list.json is
# the binary's tools/list captured once into a literal, so a changed tool
# (name, description, schema) fails here and the literal is re-pinned by hand.
TOOLS_LIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools_list.json")
with open(TOOLS_LIST_PATH) as _f:
    TOOLS = json.load(_f)
TOOL_NAMES = [t["name"] for t in TOOLS]


def legacy_init_result(version=LEGACY_VERSION):
    return {"protocolVersion": version, "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO}


SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


def normalized(obj):
    """A deep copy with every serverInfo version replaced by "<semver>" when
    it is one, so a whole-reply assert survives a release bump and still
    fails on a malformed version."""
    if isinstance(obj, dict):
        out = {k: normalized(v) for k, v in obj.items()}
        if out.get("name") == "chromium-bridge" and SEMVER.match(str(out.get("version", ""))):
            out["version"] = "<semver>"
        return out
    if isinstance(obj, list):
        return [normalized(v) for v in obj]
    return obj


def rpc_result(_id, result):
    return {"jsonrpc": "2.0", "id": _id, "result": result}


def rpc_error(_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": _id, "error": error}


def tool_text(payload):
    """The text block the server renders a tool's data as: serde_json's
    compact, key-sorted serialization."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def tool_result(_id, payload, modern=False):
    result = {"content": [{"type": "text", "text": tool_text(payload)}], "isError": False}
    if modern:
        result["resultType"] = "complete"
    return rpc_result(_id, result)


def tool_error(_id, code, message):
    """A tool-level failure: an isError result carrying the taxonomy code,
    never a JSON-RPC error."""
    return rpc_result(_id, {"content": [{"type": "text", "text": f"Error [{code}]: {message}"}],
                            "isError": True})


def unsupported_version(_id, requested):
    """The per-request -32022 for a wrong string version: the full supported
    set plus the raw requested value."""
    return rpc_error(_id, -32022, "Unsupported protocol version",
                     {"requested": requested, "supported": SUPPORTED_VERSIONS})


# The error displays the server renders as `Error [CODE]: <display>` text.
BRIDGE_KILLED = ("the bridge kill switch is engaged - all bridge activity is refused until it is "
                 "explicitly released (`chromium-bridge unkill`)")
CONNECTION_LOST = "extension connection lost while waiting for response"


def browser_ambiguous(labels):
    return (f"multiple browsers are connected ({', '.join(labels)}) - pass the `browser` "
            "argument to pick one (see list_browsers)")


def browser_not_found(label, labels):
    return f"no connected browser is labeled '{label}' (connected: {', '.join(labels)}) - see list_browsers"


def tool_payload(reply):
    """The parsed data of a tool result (for a reply whose envelope was already
    asserted, or whose payload carries nondeterministic fields)."""
    return json.loads(reply["result"]["content"][0]["text"])


class McpClient:
    """Minimal MCP JSON-RPC client over a server's stdio. The modern_* helpers
    and discover stamp each request with the stateless _meta keys; initialize,
    ping, tools_list, and call send bare requests, served in the legacy era on
    a connection opened by initialize."""

    def __init__(self, proc):
        self.proc = proc

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def recv(self):
        return json.loads(self.proc.stdout.readline())

    def modern_params(self, params=None, version=MODERN_VERSION):
        p = dict(params or {})
        p["_meta"] = {META_VERSION_KEY: version, META_CAPS_KEY: {}}
        return p

    def modern_send(self, method, params=None, _id=1, version=MODERN_VERSION):
        self.send({"jsonrpc": "2.0", "id": _id, "method": method,
                   "params": self.modern_params(params, version)})
        return self.recv()

    def discover(self, _id=1, meta=True, version=MODERN_VERSION):
        """server/discover; meta=False sends the bare probe (no params), which
        rmcp has no served form for."""
        if not meta:
            self.send({"jsonrpc": "2.0", "id": _id, "method": "server/discover"})
            return self.recv()
        return self.modern_send("server/discover", _id=_id, version=version)

    def modern_tools_list(self, _id=2, version=MODERN_VERSION):
        return self.modern_send("tools/list", _id=_id, version=version)

    def modern_call(self, name, args, _id=3, version=MODERN_VERSION):
        return self.modern_send("tools/call", {"name": name, "arguments": args},
                                _id=_id, version=version)

    def initialize(self, version=LEGACY_VERSION, _id=1):
        self.send({"jsonrpc": "2.0", "id": _id, "method": "initialize",
                   "params": {"protocolVersion": version, "capabilities": {},
                              "clientInfo": {"name": "e2e", "version": "0.1"}}})
        return self.recv()

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


# ---------------------------------------------------------------------------
# Spawners (isolation-guarded) and process cleanup
# ---------------------------------------------------------------------------

def _drain(proc, markers=()):
    """Drain `proc`'s stderr into proc.err_lines from a daemon thread (a full
    pipe would wedge the child), setting each (needle, Event) marker on sight."""
    proc.err_lines = []

    def run():
        for line in proc.stderr:
            proc.err_lines.append(line)
            for needle, event in markers:
                if needle in line:
                    event.set()

    proc.drain = threading.Thread(target=run, daemon=True)
    proc.drain.start()


def start_server(bin_path=None, env=None):
    """Spawn an MCP server (text stdio; its stderr is drained into err_lines).
    `bin_path` lets the attestation tests run a copy of the binary."""
    require_isolated(env)
    proc = subprocess.Popen([bin_path or BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)
    _drain(proc)
    return proc


def server_stderr(proc):
    """The server's stderr so far; complete once the server has exited."""
    if proc.poll() is not None:
        proc.drain.join(timeout=2)
    return "".join(proc.err_lines)


# The host's stderr markers on its way up (src/packages/core/src/native_host.rs):
# "connected" fires after the socket connect (the server has accepted it),
# "ready" once the bridge handshake completes.
HOST_CONNECTED = b"connected to MCP server bridge socket"
HOST_READY = b"bridge handshake complete"


def start_bridge_host(label=None, env=None, bin_path=None):
    """Spawn `chromium-bridge --native-host` the way Chrome does: binary stdio
    (frames are raw bytes). It dials the server's socket and passes attestation
    because it is the same binary; this side plays the extension. `label` is
    the per-browser identity (`--label`); None lands in the "default" slot.
    nh.connected / nh.ready are set from the stderr markers."""
    require_isolated(env)
    cmd = [bin_path or BIN, "--native-host"]
    if label is not None:
        cmd += ["--label", label]
    nh = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env)
    nh.connected = threading.Event()
    nh.ready = threading.Event()
    _drain(nh, ((HOST_CONNECTED, nh.connected), (HOST_READY, nh.ready)))
    return nh


def host_stderr(nh):
    return b"".join(nh.err_lines).decode("utf-8", "replace")


def wait_host_ready(nh, timeout=5):
    """Block until the host reports a completed bridge handshake; a timeout is
    a regression, raised loudly (and the host reaped, not leaked)."""
    if not nh.ready.wait(timeout):
        kill(nh)
        raise TimeoutError(f"native host did not complete the bridge handshake within {timeout}s")


def kill(proc):
    """SIGKILL a process this harness started (a specific pid, never a
    pattern): no handler runs, no cleanup happens, the crash shape."""
    if proc is not None and proc.poll() is None:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def reap(proc, timeout=5):
    """Stop a process this harness started and release its pipes: stdin EOF
    first (a server exits when its last harness detaches, a host when Chrome
    disconnects), SIGKILL if it is still up after `timeout`."""
    if proc is None:
        return
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    except OSError:
        pass
    if proc.poll() is None:
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            kill(proc)
    drain = getattr(proc, "drain", None)
    if drain is not None:
        drain.join(timeout=2)
    for pipe in (proc.stdout, proc.stderr):
        try:
            if pipe is not None:
                pipe.close()
        except OSError:
            pass


def connect_bridge(lf, timeout=5):
    """A raw connection to the bridge socket (Unix-domain on Unix, loopback TCP
    on Windows): what a foreign, non-binary process would do."""
    if os.name == "nt":
        host, port = lf["endpoint"].rsplit(":", 1)
        return socket.create_connection((host, int(port)), timeout=timeout)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(lf["endpoint"])
    return s


def foreign_peer_outcome(lf):
    """Connect as a foreign peer and return what the server sent before
    closing: b"" is the attestation drop (no challenge), anything else a leak."""
    s = connect_bridge(lf)
    s.settimeout(3)
    try:
        return s.recv(4096)
    except socket.timeout:
        return b"__no_eof__"
    finally:
        s.close()


def call_with_timeout(fn, seconds):
    """(finished, value) for `fn` run on a daemon thread; a blocking read that a
    regression never satisfies fails the check instead of hanging the gate.
    An exception from `fn` is re-raised."""
    box = {}

    def run():
        try:
            box["v"] = fn()
        except Exception as e:  # noqa: BLE001 - re-raised in the caller's thread
            box["e"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        return (False, None)
    if "e" in box:
        raise box["e"]
    return (True, box.get("v"))


def read_reply_or_eof(proc, timeout=10):
    """One guarded readline on `proc`'s stdout: the line ("" on EOF), None on
    timeout, or an error marker on a read exception, each distinct so an EOF
    assertion can never pass by accident."""
    def read():
        try:
            return proc.stdout.readline()
        except (ValueError, OSError) as e:
            return f"<readline error: {e!r}>"

    finished, line = call_with_timeout(read, timeout)
    return line if finished else None


# ---------------------------------------------------------------------------
# Playing the extension: answering BridgeReqs the server forwards to a host
# ---------------------------------------------------------------------------

def serve_bridge_req(nh, responder):
    """Read one BridgeReq off the host's stdout, reply with `responder(req)`
    as an NM frame on its stdin. Returns the request, or None on EOF."""
    req = nm_read(nh)
    if req is None:
        return None
    nm_write(nh, responder(req))
    return req


def without_id(frame):
    """A BridgeReq minus its server-assigned correlation id, for whole-frame
    asserts."""
    return {k: v for k, v in frame.items() if k != "id"}


class Served:
    """One BridgeReq answered from a worker thread with `data`. request()
    returns the frame the host forwarded (its id removed) or fails when none
    arrived in time."""

    def __init__(self, nh, data):
        self.frame = None

        def run():
            try:
                self.frame = serve_bridge_req(
                    nh, lambda req: {"id": req["id"], "ok": True, "data": data})
            except (ValueError, OSError):
                pass  # the host was torn down mid-read

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def request(self, timeout=3):
        self.thread.join(timeout)
        if self.frame is None:
            raise AssertionError(f"no BridgeReq reached the host within {timeout}s")
        return without_id(self.frame)


def serve_bridge_loop(nh, responder):
    """Serve BridgeReqs on `nh` from a daemon thread until its stdout closes,
    for tests where the request count is not known up front (list_browsers
    fans out one tab_list per live browser). The returned box carries
    `error`, any unexpected exception from the responder, which the test
    asserts is None (a daemon thread's exception would otherwise vanish)."""
    box = {"error": None}

    def loop():
        try:
            while serve_bridge_req(nh, responder) is not None:
                pass
        except (ValueError, OSError):
            pass  # host torn down mid-read; the test is done with it
        except Exception as e:  # noqa: BLE001 - surfaced via the box
            box["error"] = e

    threading.Thread(target=loop, daemon=True).start()
    return box


# ---------------------------------------------------------------------------
# Presence-gated CLI commands (unkill, pair-client) on a pty
# ---------------------------------------------------------------------------

_enclave_key = None


def enclave_key_present(env=None):
    """Whether a Secure Enclave enrollment key exists here. When it does,
    presence-gated commands raise a real Touch ID prompt an automated run
    cannot answer, so callers skip (tests never raise real prompts). Only a
    definitive `key: none` line lets them run; off macOS there is no
    hardware rung. Read-only, never prompts; cached per process."""
    global _enclave_key
    if _enclave_key is not None:
        return _enclave_key
    _enclave_key = _probe_enclave_key(env)
    return _enclave_key


def _probe_enclave_key(env):
    if sys.platform != "darwin":
        return False
    try:
        r = subprocess.run([BIN, "enclave-status"], capture_output=True,
                           text=True, env=env, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return True
    if r.returncode != 0:
        return True
    for line in r.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("key:"):
            rest = stripped[len("key:"):].split()
            # The not-enrolled line is exactly `key:        none (run ...)`;
            # match the first token so `nonetheless` can never read as none.
            return not (rest and rest[0] == "none")
    return True


def run_with_cli_presence(args, phrase="release", check=True, timeout=15, env=None):
    """Run a capability-restoring subcommand (`unkill`, `pair-client`) through
    its presence floor: with no enrollment key the hardware rung is
    Unavailable and the CLI floor reads the confirmation phrase from a
    terminal, so the command runs on a pty and the phrase is typed. Callers
    guard with enclave_key_present(). Unix only."""
    import pty

    master, slave = pty.openpty()
    try:
        p = subprocess.Popen([BIN, *args], stdin=slave,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding="utf-8", env=env)
        os.close(slave)
        slave = -1
        os.write(master, (phrase + "\n").encode())
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
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


def runtime_file(name):
    """A file in the isolated runtime dir beside the lock (audit.log,
    clients.json, revocation.json)."""
    return os.path.join(os.path.dirname(LOCK), name)


def read_jsonl(path):
    try:
        with open(path) as f:
            return [json.loads(ln) for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


def read_revocation():
    with open(runtime_file("revocation.json")) as f:
        return json.load(f)


def reset_enrollment():
    """Back to the unenrolled bootstrap: clients.json AND the revocation
    record. Removing only the allowlist is not a reset but detectable
    tampering (its enrollment latch lives in the record), so a test that
    paired must drop both."""
    require_isolated()
    for name in ("clients.json", "revocation.json"):
        try:
            os.remove(runtime_file(name))
        except FileNotFoundError:
            pass


def audit_records():
    """Every record in the audit trail, the rotated file first, exactly as the
    CLI reader joins them."""
    return read_jsonl(runtime_file("audit.log.1")) + read_jsonl(runtime_file("audit.log"))


# ---------------------------------------------------------------------------
# The TestCase base
# ---------------------------------------------------------------------------

def capture_tools_list():
    """Re-pin tools_list.json from the binary's own tools/list reply (run
    `moon run fmt-ts` afterwards; the suite's catalogue test then pins it)."""
    ensure_binary()
    isolate("bb-capture-")
    remove_lock()
    srv = start_server()
    try:
        if wait_lock(srv) is None:
            sys.exit("the server wrote no lock; see its stderr: " + server_stderr(srv))
        tools = McpClient(srv).modern_tools_list(_id=1)["result"]["tools"]
    finally:
        reap(srv)
    with open(TOOLS_LIST_PATH, "w") as f:
        json.dump(tools, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"{len(tools)} tools written to {TOOLS_LIST_PATH}", file=sys.stderr)


class BridgeCase(unittest.TestCase):
    """Spawn helpers that register their cleanup, so a failing assertion never
    leaks a server or host past the test."""

    maxDiff = None

    def server(self, env=None, bin_path=None, wait=True, clear_stale_lock=True):
        """A fresh MCP server, reaped at cleanup. With `wait`, the server must
        write its lock, kept on `proc.lock`. A stale lock is cleared first
        unless the test is about recovering from one."""
        if clear_stale_lock:
            remove_lock(env)
        proc = start_server(bin_path=bin_path, env=env)
        self.addCleanup(reap, proc)
        if wait:
            proc.lock = wait_lock(proc)
            self.assertIsNotNone(proc.lock, f"the server wrote its lock file; stderr: {server_stderr(proc)}")
        return proc

    def instance(self, env=None):
        """Another instance started against whatever lock exists (a relay to a
        live broker, or one racer among concurrent starts); reaped at cleanup."""
        proc = start_server(env=env)
        self.addCleanup(reap, proc)
        return proc

    def host(self, label=None, env=None, bin_path=None, ready=True):
        """A native host, reaped at cleanup; with `ready`, its bridge handshake
        must complete."""
        nh = start_bridge_host(label=label, env=env, bin_path=bin_path)
        self.addCleanup(reap, nh)
        if ready:
            wait_host_ready(nh)
        return nh

    def legacy_client(self, proc):
        """An MCP client past the legacy initialize handshake."""
        c = McpClient(proc)
        c.initialize()
        c.initialized()
        return c

    def private_runtime(self, prefix):
        """A further-isolated runtime dir for a test whose state (pairing,
        policy) must not leak into the suite's shared dir. LOCK follows it for
        the test's duration. Returns the child env."""
        global LOCK
        rundir = new_runtime_dir(prefix)
        env = dict(os.environ, XDG_RUNTIME_DIR=rundir,
                   XDG_CONFIG_HOME=os.path.join(rundir, "config"))
        if sys.platform == "darwin":
            env["HOME"] = rundir
        saved = LOCK
        LOCK = lock_path(rundir)

        def restore():
            global LOCK
            LOCK = saved
            shutil.rmtree(rundir, ignore_errors=True)

        self.addCleanup(restore)
        return env

    def skip_unless_unix(self, what):
        if os.name == "nt":
            self.skipTest(f"{what} is Unix-only (Windows keeps loopback TCP)")

    def skip_if_enrolled(self):
        """The presence floor is driven on a pty; an enrolled Secure Enclave key
        reaches the Touch ID rung first and would raise a real prompt. That
        path is covered by `moon run touchid-gates`."""
        if enclave_key_present():
            self.skipTest("an enrolled Secure Enclave key would raise a real Touch ID prompt")

    def bounded(self, label, fn, secs=20):
        """`fn()` under a hard timeout: a hang is a failed test, never a stuck
        gate."""
        finished, value = call_with_timeout(fn, secs)
        self.assertTrue(finished, f"{label} did not complete within {secs}s")
        return value

    def assertToolsList(self, reply, _id, envelope):
        """The whole tools/list reply: the full catalogue literal plus
        `envelope` as everything else in the result. Returns the served tools."""
        self.assertEqual(reply, rpc_result(_id, {**envelope, "tools": TOOLS}))
        return reply["result"]["tools"]

    def enrolled_broker(self, client):
        """This interpreter paired as a trusted client, with a serving broker
        and an attached browser; `client(server)` opens the MCP session.
        Enrollment is reset at cleanup. Skips where the presence floor or
        harness attestation is unavailable."""
        self.skip_if_enrolled()
        self.skip_unless_unix("harness attestation")
        reset_enrollment()
        self.addCleanup(reset_enrollment)
        run_with_cli_presence(["pair-client", "--name", "pytest", "--this-parent"])
        srv = self.server()
        c = client(srv)
        nh = self.host()
        return srv, c, nh

    def assertRefusedToStart(self, proc, needle=None):
        """`proc` never became the broker: no lock, exit status 1, and (when
        given) `needle` in its stderr naming the refusal."""
        self.assertIsNone(wait_lock(proc, timeout=3), "a refused server must not write the lock")
        self.assertExits(proc, 5, "a refused server exits")
        self.assertEqual(proc.returncode, 1, server_stderr(proc))
        if needle is not None:
            self.assertIn(needle, server_stderr(proc))

    def assertExits(self, proc, timeout, msg):
        """`proc` exits on its own within `timeout`; the handle stays reaped
        by cleanup either way."""
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        self.assertIsNotNone(proc.poll(), msg)


if __name__ == "__main__":
    if sys.argv[1:] != ["--capture-tools-list"]:
        sys.exit("usage: harness.py --capture-tools-list")
    capture_tools_list()
