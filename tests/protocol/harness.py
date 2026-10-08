"""Shared harness for the protocol suites (e2e, adversarial, chaos).

The suites drive the real release binary as subprocesses and speak its wire
protocols from the outside: Native-Messaging frames to a `--native-host`, MCP
JSON-RPC over the server's stdio, raw connects to the bridge socket. This
module holds what they share: runtime-dir isolation, the process spawners, the
wire helpers, the whole-reply expectations, and the TestCase base that reaps
every process a test started.

Safety rule: every binary spawned here runs inside a private, per-run runtime
dir (`isolate`), so the lock, socket, pairing state, and broker logic can
never reach the developer's real bridge. `isolate` proves the dir took by
asking the binary itself (`doctor --paths`) where its lock resolves, every
child starts through the one `spawn` that re-checks the env it will see, and
`teardown` removes every dir on every exit path (tearDownModule, SIGTERM,
SIGINT, atexit) while `sweep_stale_runtime_dirs` clears what a run killed
outright left behind.

Stdlib only, on purpose: an independent implementation of the protocols with
no dependencies is what makes these suites catch framing and encoding bugs the
Rust types cannot see. Never add a package.
"""
import atexit
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import signal
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
                   "genkan" + (".exe" if os.name == "nt" else ""))

# Set by isolate(); every spawner re-checks them through require_isolated().
RUNDIR = None
LOCK = None
# Every runtime dir this process created; a child may only be pointed at one of these.
OWNED_RUNTIME_DIRS = set()
# Every process spawn() started, so teardown can stop the ones a killed run leaves behind.
CHILDREN = []
# Names the creating process in each runtime dir; the sweep judges staleness by it.
OWNER_FILE = "harness.pid"
# A dir with no owner record is kept this long: it may sit between its mkdtemp and its record write.
UNRECORDED_DIR_FRESH_SECS = 60


def within(child, parent):
    """True when `child` resolves inside `parent`. realpath + commonpath, so a
    symlinked temp root (/var -> /private/var on macOS) and a lexical cousin
    (/tmp/genkan vs /tmp/genkan-evil) are both handled."""
    try:
        p = os.path.realpath(parent)
        return os.path.commonpath([os.path.realpath(child), p]) == p
    except ValueError:
        return False


def lock_path(rundir):
    # Mirrors LockFile::path() in src/packages/core/src/ipc/lockfile.rs.
    return os.path.join(rundir, "genkan", "run.lock")


def runtime_dir_var(platform=os.name):
    """The variable the binary resolves its runtime dir from (ipc/runtime_dir.rs): LOCALAPPDATA
    on Windows, where XDG_RUNTIME_DIR is ignored, so a child pointed only at
    XDG there would run against the real per-user dir."""
    return "LOCALAPPDATA" if platform == "nt" else "XDG_RUNTIME_DIR"


def runtime_env(rundir, platform=os.name):
    """The variables a child must see to run inside `rundir`."""
    env = {"XDG_RUNTIME_DIR": rundir, "XDG_CONFIG_HOME": os.path.join(rundir, "config")}
    if platform == "nt":
        env["LOCALAPPDATA"] = rundir
    if sys.platform == "darwin":
        env["HOME"] = rundir
    return env


def new_runtime_dir(prefix):
    """A fresh private runtime dir directly under the OS temp dir (a nested
    one overruns the Unix socket path limit), recorded as this process's so
    teardown removes it and a later sweep can tell it from a live run's."""
    rundir = tempfile.mkdtemp(prefix=prefix)
    OWNED_RUNTIME_DIRS.add(rundir)
    with open(os.path.join(rundir, OWNER_FILE), "w") as f:
        f.write(f"{os.getpid()}\n")
    return rundir


def remove_runtime_dir(rundir):
    """Remove a dir this process created. A failure raises: a dir that
    survives is a leak the run reports, never one it ignores."""
    shutil.rmtree(rundir)
    OWNED_RUNTIME_DIRS.discard(rundir)


def teardown():
    """Stop every child still running and remove every runtime dir this
    process created. Idempotent, so tearDownModule, the signal handlers, and
    the atexit backstop all call it. Raises naming the dirs that survived."""
    alive = [proc for proc in CHILDREN if proc.poll() is None]
    for proc in alive:
        kill(proc)
    CHILDREN.clear()
    if alive:
        print(f"[isolation] stopped {len(alive)} process(es) still running at teardown",
              file=sys.stderr)
    leaked = []
    for rundir in sorted(OWNED_RUNTIME_DIRS):
        try:
            remove_runtime_dir(rundir)
        except OSError as e:
            leaked.append(f"{rundir}: {e}")
    if leaked:
        raise RuntimeError("runtime dirs survived teardown:\n" + "\n".join(leaked))


def _teardown_reporting():
    try:
        teardown()
    except RuntimeError as e:
        print(f"[isolation] {e}", file=sys.stderr)


def _exit_on_signal(signum, frame):
    """A terminating signal ends the interpreter without atexit (the path a
    tool timeout or a cancelled pre-commit hook takes), so teardown runs
    here, then the default action so the parent sees the signal."""
    _teardown_reporting()
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


def guard_exit():
    """Run teardown on every exit path this process can see."""
    atexit.register(_teardown_reporting)
    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), _exit_on_signal)


# pid_t is a 32-bit int everywhere these suites run; a larger value names no process.
PID_MAX = 2**31 - 1


def read_owner(rundir):
    """The pid recorded in `rundir`, or None when there is no record. A record
    that cannot be read, or does not spell one positive pid, raises: the sweep
    must not mistake it for an absent owner."""
    record = os.path.join(rundir, OWNER_FILE)
    try:
        with open(record) as f:
            text = f.read()
    except FileNotFoundError:
        if os.path.lexists(record):
            raise
        return None
    if not re.fullmatch(r"[1-9][0-9]*", text.strip()) or int(text) > PID_MAX:
        raise ValueError(f"malformed {OWNER_FILE}: {text!r}")
    return int(text)


def pid_alive(pid):
    """Whether a process `pid` exists. Another user's process and a zombie
    count as alive: the sweep never guesses."""
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _windows_pid_alive(pid):
    """os.kill(pid, 0) TERMINATES a process on Windows (CPython maps every
    signal but the console events to TerminateProcess), so existence is read
    through a query-only handle. Only a definite answer reads as dead: an
    OpenProcess failure other than "no such pid" or a failed exit-code query
    keeps the dir."""
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    process_query_limited_information, still_active, error_invalid_parameter = 0x1000, 259, 87
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return ctypes.get_last_error() != error_invalid_parameter
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def _stale_reason(path, now):
    """Why `path` may go, or None while a process may still own it."""
    owner = read_owner(path)
    if owner is None:
        if now - os.path.getmtime(path) < UNRECORDED_DIR_FRESH_SECS:
            return None
        return "no owner recorded"
    if pid_alive(owner):
        return None
    return f"harness pid {owner} is gone"


def sweep_stale_runtime_dirs(prefix, root):
    """Remove the `prefix` dirs under `root` whose creating process is gone:
    the heal for a run killed before its teardown. A dir whose recorded pid
    is alive, or whose record cannot be read, is never touched. Prints and
    returns what it removed."""
    removed = []
    now = time.time()
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not name.startswith(prefix) or os.path.islink(path) or not os.path.isdir(path):
            continue
        try:
            reason = _stale_reason(path, now)
        except (OSError, ValueError) as e:
            print(f"[isolation] kept {path}: owner record unreadable ({e})", file=sys.stderr)
            continue
        if reason is None:
            continue
        try:
            shutil.rmtree(path)
        except OSError as e:
            print(f"[isolation] could not remove stale runtime dir {path}: {e}", file=sys.stderr)
            continue
        removed.append(path)
        print(f"[isolation] removed stale runtime dir {path} ({reason})", file=sys.stderr)
    return removed


def isolate(prefix):
    """Point every future subprocess at a fresh private runtime dir and prove
    it took; refuse to run otherwise. The proof is the binary's own word: a
    resolver that read a variable this env does not set would place the lock
    outside the dir, and `doctor --paths` would say so."""
    global RUNDIR, LOCK
    sweep_stale_runtime_dirs(prefix, tempfile.gettempdir())
    guard_exit()
    rundir = new_runtime_dir(prefix)
    os.environ.update(runtime_env(rundir))
    lock = lock_path(rundir)
    if not (os.path.isdir(rundir) and within(rundir, tempfile.gettempdir())):
        sys.exit("REFUSING TO RUN: isolation dir is not a fresh temp dir")
    if not within(lock, rundir):
        sys.exit("REFUSING TO RUN: lock path escaped the isolation dir")
    RUNDIR, LOCK = rundir, lock
    resolved = binary_lock_path()
    if os.path.realpath(resolved) != os.path.realpath(lock):
        sys.exit(f"REFUSING TO RUN: the binary resolves its lock to {resolved}, not {lock}")
    print(f"[isolation] per-run runtime dir: {rundir}", file=sys.stderr)
    print(f"[isolation] lock path:           {lock}", file=sys.stderr)
    return rundir


DOCTOR_LOCK_LINE = "lock file:"


def binary_lock_path():
    """Where the binary resolves its lock under this process's env, read off
    `doctor --paths`, which prints the resolved paths and touches nothing."""
    report = run_cli(["doctor", "--paths"])
    for line in report.stdout.splitlines():
        if line.startswith(DOCTOR_LOCK_LINE):
            return line[len(DOCTOR_LOCK_LINE):].strip()
    sys.exit(f"REFUSING TO RUN: doctor --paths printed no {DOCTOR_LOCK_LINE!r} line:\n"
             f"{report.stdout}{report.stderr}")


def require_isolated(env=None, platform=os.name):
    """The runtime dir a child would see (`env`, else this process's, read
    from the variable the binary honors on `platform`) is one this harness
    created, and LOCK points inside it."""
    runtime = (os.environ if env is None else env).get(runtime_dir_var(platform))
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
SERVER_INFO = {"name": "genkan", "version": "<semver>"}
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
        if out.get("name") == "genkan" and SEMVER.match(str(out.get("version", ""))):
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
                 "explicitly released (`genkan unkill`)")
CONNECTION_LOST = "extension connection lost while waiting for response"


def browser_ambiguous(labels):
    return (f"multiple browsers are connected ({', '.join(labels)}) - pass the `browser` "
            "argument to pick one (see list_browsers)")


def browser_not_found(label, labels):
    return f"no connected browser is labeled '{label}' (connected: {', '.join(labels)}) - see list_browsers"


def tool_payload(reply):
    """The parsed data of a tool result whose payload needs normalizing before
    a whole assert."""
    return json.loads(reply["result"]["content"][0]["text"])


def browsers_listing(reply):
    """The list_browsers payload with its browsers in label order: the server
    lists them in registry order, which the hosts' connect race decides."""
    payload = tool_payload(reply)
    return {**payload, "browsers": sorted(payload["browsers"], key=lambda b: b["label"])}


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


def spawn(args, env=None, bin_path=None, **popen):
    """The one place the binary starts, so no child runs before the isolation
    check passes on the env it will see. `bin_path` runs a copy of the binary
    (the attestation tests)."""
    require_isolated(env)
    proc = subprocess.Popen([bin_path or BIN, *args], env=env, **popen)
    CHILDREN[:] = [p for p in CHILDREN if p.poll() is None]
    CHILDREN.append(proc)
    return proc


def run_cli(args, env=None, input=None, stdin=None, check=False, timeout=15):
    """A CLI subcommand run to completion. `stdin` replaces the pipe `input`
    would be written to: the presence floor reads its phrase from a terminal,
    so run_with_cli_presence passes a pty here."""
    if stdin is None:
        stdin = subprocess.PIPE if input is not None else subprocess.DEVNULL
    p = spawn(args, env=env, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
              text=True, encoding="utf-8")
    try:
        out, err = p.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        raise
    result = subprocess.CompletedProcess(p.args, p.returncode, out, err)
    if check and result.returncode != 0:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {err}")
    return result


def start_server(bin_path=None, env=None):
    """Spawn an MCP server (text stdio; its stderr is drained into err_lines)."""
    proc = spawn([], env=env, bin_path=bin_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE, text=True, encoding="utf-8")
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
    """Spawn `genkan --native-host` the way Chrome does: binary stdio
    (frames are raw bytes). It dials the server's socket and passes attestation
    because it is the same binary; this side plays the extension. `label` is
    the per-browser identity (`--label`); None lands in the "default" slot.
    nh.connected / nh.ready are set from the stderr markers."""
    args = ["--native-host"]
    if label is not None:
        args += ["--label", label]
    nh = spawn(args, env=env, bin_path=bin_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
               stderr=subprocess.PIPE)
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
    """A raw connection to the Unix-domain bridge socket: what a foreign,
    non-binary process would do. Unix only (Windows bridges over a named
    pipe); callers skip through skip_unless_unix."""
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

def run_with_cli_presence(args, phrase="release", check=True, timeout=15, env=None):
    """Run a capability-restoring subcommand (`unkill`, `pair-client`) through
    its presence floor: the CLI reads the confirmation phrase from a terminal,
    so the command runs on a pty with the phrase already typed (the pty queues
    it until the child reads). Unix only."""
    import pty

    master, slave = pty.openpty()
    try:
        os.write(master, (phrase + "\n").encode())
        return run_cli(args, env=env, stdin=slave, check=check, timeout=timeout)
    finally:
        os.close(slave)
        os.close(master)


def runtime_file(name):
    """A file in the isolated runtime dir beside the lock (audit.log,
    trust.json)."""
    return os.path.join(os.path.dirname(LOCK), name)


def read_jsonl(path):
    try:
        with open(path) as f:
            return [json.loads(ln) for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


# ---------------------------------------------------------------------------
# Whole-record expectations for the records the binary keeps (lock, trust,
# audit) and the volatile fields in them
# ---------------------------------------------------------------------------

class Volatile:
    """A field no expectation can spell (a timestamp, a nonce, a secret): in a
    whole-record assert its `token` stands in for any value `shape` accepts,
    so the record still fails on a malformed one."""

    def __init__(self, token, shape):
        self.token = token
        self.shape = shape

    def __call__(self, value):
        return self.token if self.shape(value) else Malformed(value)


class Malformed:
    """A value its Volatile's shape refused, kept distinct from the token: a
    raw value spelled like the token must not pass."""

    def __init__(self, value):
        self.value = value

    def __eq__(self, other):
        return isinstance(other, Malformed) and other.value == self.value

    def __repr__(self):
        return f"Malformed({self.value!r})"


def _hex(digits):
    return lambda v: isinstance(v, str) and re.fullmatch(f"[0-9a-f]{{{digits}}}", v) is not None


def _int(minimum):
    return lambda v: type(v) is int and v >= minimum


def _base64url_bytes(count):
    """Canonical unpadded base64url of exactly `count` bytes: the engine in
    webauthn/base64url.rs refuses nonzero trailing bits, so a round trip must
    reproduce the text."""
    def accepts(v):
        if not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", v):
            return False
        try:
            raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
        except (binascii.Error, ValueError):
            return False
        return len(raw) == count and base64.urlsafe_b64encode(raw).rstrip(b"=").decode() == v
    return accepts


UNIX_SECS = Volatile("<unix>", _int(1))
UNIX_MS = Volatile("<unix_ms>", _int(1))
DURATION_MS = Volatile("<ms>", _int(0))
SECRET = Volatile("<secret>", _hex(32))
BASE64URL = Volatile("<base64url>", _base64url_bytes(32))


def pipe_endpoint(pid):
    """The Windows endpoint, PipeName::for_broker in ipc/platform/windows/mod.rs:
    the runtime dir's path hashed (SHA-256, first 16 bytes) then the broker's
    pid. The harness sets LOCALAPPDATA itself, so the binary's runtime dir is
    dirname(LOCK) byte for byte and the name is pinned exactly."""
    leaf = hashlib.sha256(os.path.dirname(LOCK).encode()).hexdigest()[:32]
    return rf"\\.\pipe\genkan-{leaf}-{pid}"


def placeholders(obj, **volatile):
    """A deep copy of `obj` with each named key's value replaced by its
    Volatile's token wherever the key appears."""
    if isinstance(obj, dict):
        return {k: volatile[k](v) if k in volatile else placeholders(v, **volatile)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [placeholders(v, **volatile) for v in obj]
    return obj


def socket_path():
    # Mirrors RuntimeDir::socket_path() in src/packages/core/src/ipc/runtime_dir.rs.
    return os.path.join(os.path.dirname(LOCK), "run.sock")


def lock_published_by(proc):
    """The whole lock a live server `proc` publishes (ipc/lockfile.rs): the
    socket beside the lock (a named pipe on Windows), a per-run secret, its
    pid."""
    endpoint = pipe_endpoint(proc.pid) if os.name == "nt" else socket_path()
    return {"endpoint": endpoint, "secret": SECRET.token, "pid": proc.pid}


def lock_record(lf):
    """A lock as read, its secret as the placeholder, for comparing with
    lock_published_by."""
    return placeholders(lf, secret=SECRET)


# migrations/trust.rs LADDER; a rung added there re-pins this by hand.
TRUST_VERSION = 0


def trust_record(epoch, clients, killed=False, kill_epoch=0):
    """The whole trust record (trust.rs) after `epoch` mutations: `clients` is
    None before any pairing, else the entries in pairing order."""
    return {"version": TRUST_VERSION, "epoch": epoch, "killed": killed, "kill_epoch": kill_epoch,
            "host_key_epoch": 0, "policy_epoch": 0, "lang_epoch": 0, "clients": clients,
            "enrollments": []}


def client_entry(name, kind, value):
    """One trusted client as the trust record and client_list carry it."""
    return {"name": name, "anchor": {"kind": kind, "value": value}, "added_unix": UNIX_SECS.token}


# The anchor runs to the presence suffix: a signer is any non-empty string, spaces included.
PAIRED = re.compile(r"^paired trusted client '[^']+' on (hash|signer) (.+) \(user presence: \w+\)$", re.M)


def pair_client(name, *anchor, env=None):
    """Pair `name` through the CLI presence floor; `anchor` is the --hash,
    --signer, or --this-parent choice. Returns the entry as the CLI reports
    it: with --this-parent the anchor is measured, so only the CLI can
    spell it."""
    out = run_with_cli_presence(["pair-client", "--name", name, *anchor], env=env).stdout
    m = PAIRED.search(out)
    if m is None:
        raise AssertionError(f"pair-client reported no pairing:\n{out}")
    return client_entry(name, m[1], m[2])


def read_trust():
    """The trust record on disk, pairing times as the placeholder, for
    comparing with trust_record."""
    with open(runtime_file("trust.json")) as f:
        return placeholders(json.load(f), added_unix=UNIX_SECS)


def client_list_result(nh):
    """Ask the host `nh` for its trusted-client list; the whole reply, pairing
    times as the placeholder."""
    nm_write(nh, {"type": "client_list"})
    return placeholders(nm_read(nh), added_unix=UNIX_SECS)


def reset_enrollment():
    """Back to the unenrolled bootstrap: remove the one trust record (paired
    clients, kill latch, epoch). Deleting it is the documented same-user
    revert to the open bootstrap, pinned live by A19."""
    require_isolated()
    try:
        os.remove(runtime_file("trust.json"))
    except FileNotFoundError:
        pass


# audit.rs AUDIT_VERSION.
AUDIT_VERSION = 1


def audit_record(event_kind, **fields):
    """One expected audit.log record (audit.rs AuditRecord): the kind and the
    fields that kind carries; the timestamp is the placeholder."""
    return {"v": AUDIT_VERSION, "ts_ms": UNIX_MS.token, "event_kind": event_kind, **fields}


def tool_call_record(req, outcome, code=None, tool="tab_list", **route):
    """The audit record of one tool call: its process-wide request number, the
    verdict, and the browser `route` (name, conn) when the test pins it; the
    duration is the placeholder."""
    rec = audit_record("tool_call", outcome=outcome, tool=tool, req=req, dur_ms=DURATION_MS.token,
                       **route)
    if code is not None:
        rec["code"] = code
    return rec


def audit_records(kinds=None):
    """Every record in the audit trail, the rotated file first, as the CLI
    reader joins them, timestamps and durations as placeholders. `kinds`
    keeps only those event kinds: attach and admit records interleave with
    the decisions a test is about."""
    records = read_jsonl(runtime_file("audit.log.1")) + read_jsonl(runtime_file("audit.log"))
    records = placeholders(records, ts_ms=UNIX_MS, dur_ms=DURATION_MS)
    if kinds is not None:
        records = [rec for rec in records if rec["event_kind"] in kinds]
    return records


# ---------------------------------------------------------------------------
# The TestCase base
# ---------------------------------------------------------------------------

def capture_tools_list():
    """Re-pin tools_list.json from the binary's own tools/list reply (run
    `moon run fmt-ts` afterwards; the suite's catalogue test then pins it)."""
    ensure_binary()
    isolate("genkan-capture-")
    try:
        remove_lock()
        srv = start_server()
        try:
            if wait_lock(srv) is None:
                sys.exit("the server wrote no lock; see its stderr: " + server_stderr(srv))
            tools = McpClient(srv).modern_tools_list(_id=1)["result"]["tools"]
        finally:
            reap(srv)
    finally:
        teardown()
    with open(TOOLS_LIST_PATH, "w") as f:
        json.dump(tools, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"{len(tools)} tools written to {TOOLS_LIST_PATH}", file=sys.stderr)


class BridgeCase(unittest.TestCase):
    """Spawn helpers that register their cleanup, so a failing assertion never
    leaks a server or host past the test. A case table calls doCleanups()
    between its rows, so only one row's processes are alive at a time."""

    maxDiff = None

    def server(self, env=None, bin_path=None, wait=True, clear_lock=True):
        """A fresh MCP server, reaped at cleanup. With `wait`, the server must
        write its lock, kept on `proc.lock`. Whatever lock is on disk is
        removed first, unless the test is about the server replacing one."""
        if clear_lock:
            remove_lock(env)
        proc = start_server(bin_path=bin_path, env=env)
        self.addCleanup(reap, proc)
        if wait:
            proc.lock = wait_lock(proc)
            self.assertLock(proc.lock, proc, f"the server published its lock; stderr: {server_stderr(proc)}")
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
        env = dict(os.environ, **runtime_env(rundir))
        saved = LOCK
        LOCK = lock_path(rundir)

        def restore():
            global LOCK
            LOCK = saved
            remove_runtime_dir(rundir)

        self.addCleanup(restore)
        return env

    def skip_unless_unix(self, what):
        if os.name == "nt":
            self.skipTest(f"{what} is Unix-only (Windows bridges over a named pipe)")

    def bounded(self, label, fn, secs=20):
        """`fn()` under a hard timeout: a hang is a failed test, never a stuck
        gate."""
        finished, value = call_with_timeout(fn, secs)
        self.assertTrue(finished, f"{label} did not complete within {secs}s")
        return value

    def assertLock(self, lf, proc, msg=None):
        """`lf` is the whole lock the live server `proc` publishes."""
        self.assertEqual(lock_record(lf), lock_published_by(proc), msg)

    def assertEventually(self, read, expected, timeout, msg=None):
        """`read()` comes to equal `expected` within `timeout` seconds (a state
        the binary reaches asynchronously); the last reading is asserted
        whole, so a timeout fails with the diff."""
        deadline = time.time() + timeout
        value = read()
        while value != expected and time.time() < deadline:
            time.sleep(0.1)
            value = read()
        self.assertEqual(value, expected, msg)

    def assertToolsList(self, reply, _id, envelope):
        """The whole tools/list reply: the full catalogue literal plus
        `envelope` as everything else in the result. Returns the served tools."""
        self.assertEqual(reply, rpc_result(_id, {**envelope, "tools": TOOLS}))
        return reply["result"]["tools"]

    def enrolled_broker(self, client):
        """This interpreter paired as a trusted client, with a serving broker
        and an attached browser; `client(server)` opens the MCP session.
        Enrollment is reset at cleanup. Skips where harness attestation is
        unavailable."""
        self.skip_unless_unix("harness attestation")
        reset_enrollment()
        self.addCleanup(reset_enrollment)
        pair_client("pytest", "--this-parent")
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
