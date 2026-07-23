#!/usr/bin/env python3
"""Adversarial break-in regression suite for chromium-bridge.

This is the socket-level attacker's view of the bridge. It drives the real
release binary as subprocesses (reusing tests/protocol/e2e.py's harness) and tries to
break in the way a hostile same-user process would: connect straight to the
bridge socket, replay/forge the handshake, flood the protocol readers, and
read the per-run secret out of any diagnostic output.

CENTRAL FACT (why this suite proves what it proves): the MCP server attests a
peer's executable identity BEFORE the HMAC handshake and before forwarding any
byte (src/mcp_server.rs accept loop: peer-UID -> attest_peer -> handshake). A
foreign peer is therefore dropped at attestation with a clean EOF, before it
can attempt replay/MAC/hex/capability tricks. So the black-box attacks here
prove ATTESTATION robustly; the protocol-level parser/MAC defenses that sit
BEHIND attestation are proven by the Rust unit/proptests referenced inline
(src/ipc.rs, src/protocol.rs) rather than faked through a path an attacker can
never reach.

Attack matrix (live MUST-BLOCK vs annotated residual):
  A1  rogue python3 socket peer                 LIVE  dropped at attestation
  A2  byte-identical binary copy                LIVE  ACCEPTED (residual, threat #4)
  A3  binary-swap-after-launch                  LIVE  python rejected; genuine OK
  A8  blank-line flood on MCP stdin leg         LIVE  server still responds
  A9  over-64MB line on MCP + NM legs           LIVE  bounded rejection, survives
  A11 no open TCP port                          LIVE  UNIX listener only
  A12 secret confidentiality                    LIVE  secret never leaks; redacted
  A14 enrolled + non-allowlisted harness        LIVE  refused, fail closed
  A15 enrolled + spoofed client NAME            LIVE  name is not authz; refused
  A16 enrolled + genuinely paired harness       LIVE  admitted; drives the bridge
  A4/A5 replay / forged-MAC                      REF  subsumed by attestation (+unit)
  A6/A7 hex / serde parser abuse                 REF  Rust hex_fuzz + serde proptests
  A10 cross-uid connect                          NOTE root/manual; 0700 dir is gate
  A13 native-messaging manifest substitution    XFAIL browser-gated on enrollment #13

SAFETY (load-bearing): every subprocess runs inside a per-run mkdtemp
XDG_RUNTIME_DIR (+ XDG_CONFIG_HOME, + HOME on macOS) so the server's lock,
socket, and takeover logic can NEVER touch the developer's real MCP server,
runtime dir, or browser. isolate() asserts this as a hard precondition and
every spawn helper re-checks it and REFUSES to run otherwise.

Run:
    python3 tests/protocol/adversarial.py
Exits 0 when every LIVE MUST-BLOCK check passes, 1 otherwise. Builds the
release binary via tests/protocol/e2e.py's ensure_binary if missing.
"""
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402  (path set above; reuse the e2e harness verbatim)

# Per-run isolation root, set by isolate(). No server may start until it is.
_RUNDIR = None

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
    return bool(cond)


def note(label):
    """An informational line for an annotated (non-live) attack: it records
    what the attack is and where its real coverage lives, without pass/failing."""
    print(f"  NOTE  {label}")


# ---------------------------------------------------------------------------
# Mandatory isolation
# ---------------------------------------------------------------------------

def isolate():
    """Point every future subprocess at a private, empty runtime dir, and prove
    it. Without this the server would bind the real lock/socket and its takeover
    logic would SIGTERM the developer's real MCP server. This MUST run before
    any server starts; the spawn helpers below re-assert it."""
    global _RUNDIR
    rundir = tempfile.mkdtemp(prefix="bb-adversarial-")
    os.environ["XDG_RUNTIME_DIR"] = rundir
    os.environ["XDG_CONFIG_HOME"] = os.path.join(rundir, "config")
    # macOS's runtime_dir() prefers XDG_RUNTIME_DIR, but doctor's manifest path
    # and any HOME fallback must be isolated too.
    if sys.platform == "darwin":
        os.environ["HOME"] = rundir
    # The lock lives at <XDG_RUNTIME_DIR>/chromium-bridge/run.lock on every unix
    # (src/ipc.rs runtime_dir). Recompute it and steer e2e's helpers at it.
    lock = os.path.join(rundir, "chromium-bridge", "run.lock")
    e2e.LOCK = lock

    # Hard precondition: refuse to run if isolation did not take. The
    # XDG_RUNTIME_DIR check is the load-bearing one -- runtime_dir() in
    # src/ipc.rs prefers XDG_RUNTIME_DIR on both macOS and Linux, so pinning it
    # to our fresh temp dir fully controls where the lock/socket land. The
    # containment checks use resolved-path commonpath, not a lexical prefix, so
    # a symlinked temp root (/var -> /private/var on macOS) cannot fool them.
    if not (rundir and os.path.isdir(rundir) and _within(rundir, tempfile.gettempdir())):
        sys.exit("REFUSING TO RUN: isolation dir is not a fresh temp dir")
    if os.environ.get("XDG_RUNTIME_DIR") != rundir:
        sys.exit("REFUSING TO RUN: XDG_RUNTIME_DIR is not the isolation dir")
    if not _within(e2e.LOCK, rundir):
        sys.exit("REFUSING TO RUN: lock path escaped the isolation dir")
    _RUNDIR = rundir
    print(f"[isolation] per-run runtime dir: {rundir}")
    print(f"[isolation] lock path:           {e2e.LOCK}")
    return rundir


def _within(child, parent):
    """True when `child` resolves inside `parent`. Uses realpath + commonpath so
    it survives symlinked temp roots and cannot be fooled by a lexical prefix
    (e.g. /tmp/bb vs /tmp/bb-evil)."""
    try:
        p = os.path.realpath(parent)
        return os.path.commonpath([os.path.realpath(child), p]) == p
    except ValueError:
        return False


def _require_isolated():
    """Every spawn and every lock touch re-checks isolation and refuses to
    proceed without it, so a bug in the setup order -- or a test invoked in
    isolation -- can never let a server bind the real lock/socket or let the
    takeover logic SIGTERM the developer's real MCP server."""
    if not (_RUNDIR
            and os.environ.get("XDG_RUNTIME_DIR") == _RUNDIR
            and _within(e2e.LOCK, _RUNDIR)):
        raise RuntimeError("REFUSING TO SPAWN: XDG isolation precondition not met")


# ---------------------------------------------------------------------------
# Spawn helpers (isolation-guarded)
# ---------------------------------------------------------------------------

def start_server(bin_path=None):
    """Start an MCP server subprocess and drain its stderr into a list so a
    flood test cannot deadlock on a full stderr pipe. Reuses e2e.BIN by default;
    a copy path is used by the binary-swap attacks."""
    _require_isolated()
    proc = subprocess.Popen([bin_path or e2e.BIN], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8")
    proc.err_lines = []
    proc.err_thread = threading.Thread(
        target=lambda: [proc.err_lines.append(ln) for ln in proc.stderr], daemon=True)
    proc.err_thread.start()
    return proc


def server_stderr(proc):
    """The server's captured stderr so far. Joins the drain thread only after
    the server has exited (the pipe has hit EOF); on a live server it returns
    the snapshot drained so far without blocking, so callers may poll it."""
    if proc.poll() is not None:
        proc.err_thread.join(timeout=2)
    return "".join(proc.err_lines)


def start_host_from(bin_path):
    """Spawn `<bin_path> --native-host`, the way Chrome does, capturing stderr
    lines and signalling `ready` when it logs the completed bridge handshake.
    Mirrors e2e.start_bridge_host but takes an arbitrary path (for copies) and
    keeps the stderr lines for assertions."""
    _require_isolated()
    nh = subprocess.Popen([bin_path, "--native-host"], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nh.ready = threading.Event()
    nh.err_lines = []

    def drain():
        for line in nh.stderr:
            nh.err_lines.append(line)
            if b"bridge handshake complete" in line:
                nh.ready.set()

    threading.Thread(target=drain, daemon=True).start()
    return nh


def host_stderr(nh):
    return b"".join(nh.err_lines).decode("utf-8", "replace")


def _call_with_timeout(fn, seconds):
    """Run `fn` on a daemon thread and give up after `seconds`. The flood/oversize
    tests read blocking pipes; if a regression stops the server producing output,
    we want the check to FAIL promptly rather than hang the CI job. Returns
    (finished, value); re-raises any exception `fn` raised."""
    box = {}

    def run():
        try:
            box["v"] = fn()
        except Exception as e:  # surfaced to the caller below
            box["e"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        return (False, None)
    if "e" in box:
        raise box["e"]
    return (True, box.get("v"))


def _reap(proc):
    if proc is None:
        return
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    except Exception:
        pass
    if proc.poll() is None:
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass


def _rm_lock():
    # Guard here too: every attack begins by clearing the lock, so this is the
    # single chokepoint that proves isolation before a test touches bridge state.
    _require_isolated()
    try:
        os.remove(e2e.LOCK)
    except FileNotFoundError:
        pass


def _tab_list_responder(req):
    assert req["op"] == "tab_list", f"unexpected op {req['op']}"
    return {"id": req["id"], "ok": True,
            "data": [{"id": 7, "title": "Adversarial Tab", "url": "https://x", "active": True}]}


# ---------------------------------------------------------------------------
# A1 - rogue same-user python3 socket peer -> dropped at attestation
# ---------------------------------------------------------------------------

def a1_rogue_python_peer():
    print("\n[A1] rogue same-user python3 socket peer (LIVE, must drop at attestation)")
    if os.name == "nt":
        note("A1 skipped: attestation is Unix-only (Windows keeps loopback TCP)")
        return
    _rm_lock()
    srv = start_server()
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A1 server up, lock written in isolated dir")
        # A raw python process is not the chromium-bridge binary. Server-side
        # attestation must drop it BEFORE any challenge byte: recv sees EOF.
        s = e2e.connect_bridge(lf)
        s.settimeout(3)
        try:
            data = s.recv(4096)
        except socket.timeout:
            data = b"__no_eof__"
        check(data == b"", "A1 signal 1: clean EOF, no challenge sent to the foreign peer")
        s.close()
        srv.stdin.close()
        srv.wait(timeout=5)
        err = server_stderr(srv)
        check("peer executable identity mismatch" in err,
              "A1 signal 2: stderr logs the executable-identity mismatch")
        # No round-trip is possible past attestation, so no session/handshake
        # was ever established for this peer.
        check("bridge handshake failed" not in err,
              "A1 signal 3: peer never reached the handshake stage")
    finally:
        _reap(srv)


# ---------------------------------------------------------------------------
# A2 - byte-identical binary copy -> ACCEPTED (documented residual, threat #4)
# ---------------------------------------------------------------------------

def a2_same_binary_copy():
    print("\n[A2] byte-identical binary copy (LIVE, documented residual: must be ACCEPTED)")
    if os.name == "nt":
        note("A2 skipped: attestation is Unix-only")
        return
    _rm_lock()
    evil = os.path.join(_RUNDIR, "evil-copy")
    shutil.copy2(e2e.BIN, evil)
    os.chmod(evil, 0o755)
    srv = start_server()
    nh = None
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A2 server up")
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        nh = start_host_from(evil)
        accepted = nh.ready.wait(6)
        check(accepted,
              "A2 byte-identical copy is ACCEPTED (DR threat #4: identical bytes = genuine)")
        if accepted:
            served = []
            t = threading.Thread(
                target=lambda: served.append(e2e.serve_bridge_req(nh, _tab_list_responder)))
            t.start()
            r = c.call("tab_list", {}, _id=5)
            t.join(timeout=3)
            data = json.loads(r["result"]["content"][0]["text"])
            check(bool(served) and data[0]["title"] == "Adversarial Tab",
                  "A2 the copy drove a full tab_list round-trip (the residual is real, not theoretical)")
    finally:
        _reap(nh)
        _reap(srv)


# ---------------------------------------------------------------------------
# A3 - binary-swap-after-launch: identity is pinned at startup, not re-read
# ---------------------------------------------------------------------------

def a3_binary_swap_after_launch():
    print("\n[A3] binary-swap-after-launch (LIVE: swap on-disk file, attestation must hold)")
    if os.name == "nt":
        note("A3 skipped: attestation is Unix-only")
        return
    _rm_lock()
    server_a = os.path.join(_RUNDIR, "server-a")
    shutil.copy2(e2e.BIN, server_a)
    os.chmod(server_a, 0o755)
    srv = start_server(bin_path=server_a)
    nh = None
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A3 server started from copy A")
        # Replace the on-disk file at path A with different bytes AFTER launch.
        # Use os.replace (rename): a running executable's file cannot be written
        # in place on Linux (ETXTBSY), but the inode can be swapped out. The
        # server's own identity was cached at startup, so this must not change
        # what it accepts.
        blob = os.path.join(_RUNDIR, "swap-b.tmp")
        with open(blob, "wb") as f:
            f.write(os.urandom(4096))
        os.replace(blob, server_a)
        # (a) A rogue python peer is STILL rejected after the swap.
        s = e2e.connect_bridge(lf)
        s.settimeout(3)
        try:
            data = s.recv(4096)
        except socket.timeout:
            data = b"__no_eof__"
        check(data == b"", "A3(a) rogue python peer still gets clean EOF after the on-disk swap")
        s.close()
        # (b) The security invariant is that the swap grants NO bypass. How the
        # genuine-liveness side lands differs by platform, and both are correct:
        #   - Linux: peer identity is the SHA256 of /proc/<pid>/exe, which follows
        #     the original (now-unlinked) inode, and self was cached at startup.
        #     A genuine host from a NEW path STILL attests: identity is pinned to
        #     the startup bytes, not to path A.
        #   - macOS: the Security framework validates the running image against
        #     its on-disk file, so overwriting path A makes the server itself
        #     FAIL CLOSED to new peers (SecCode tamper detection). That refuses
        #     service; it never silently accepts. Still no bypass.
        genuine_c = os.path.join(_RUNDIR, "genuine-c")
        shutil.copy2(e2e.BIN, genuine_c)
        os.chmod(genuine_c, 0o755)
        nh = start_host_from(genuine_c)
        attested = nh.ready.wait(6)
        if sys.platform.startswith("linux"):
            check(attested,
                  "A3(b/linux) genuine host from a new path still attests (identity pinned to startup inode, not path A)")
        else:
            check(not attested,
                  "A3(b/macos) on-disk swap makes the server fail CLOSED to new peers (tamper detected, never a silent accept)")
            check("server attestation failed" in host_stderr(nh),
                  "A3(b/macos) the new host reports the server tamper (SecCode validity), proving fail-closed")
        _reap(nh)
        srv.stdin.close()
        srv.wait(timeout=5)
        err = server_stderr(srv)
        check("peer executable identity mismatch" in err,
              "A3(a) stderr logged the python mismatch (attestation still enforced post-swap)")
    finally:
        _reap(nh)
        _reap(srv)


# ---------------------------------------------------------------------------
# A8 - blank-line flood on the MCP stdin leg -> server still responds
# ---------------------------------------------------------------------------

def a8_blank_line_flood():
    print("\n[A8] blank-line flood on MCP stdin leg (LIVE: mcp_read de-recursed, must not overflow)")
    _rm_lock()
    srv = start_server()
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A8 server up")
        # ~200k blank lines: the old recursive skip grew the stack once per line
        # and aborted under panic=abort. The de-recursed reader (69b7648) skips
        # them in constant stack, then answers the first real line.
        srv.stdin.write("\n" * 200_000)
        srv.stdin.flush()
        c = e2e.McpClient(srv)
        done, init = _call_with_timeout(c.initialize, 15)
        check(done and init and init.get("result", {}).get("protocolVersion") == "2025-06-18",
              "A8 server still answers initialize after a 200k blank-line flood")
        check(srv.poll() is None, "A8 server process survived (not aborted)")
    finally:
        _reap(srv)


# ---------------------------------------------------------------------------
# A9 - over-64MB line on both reachable legs -> bounded rejection, survives
# ---------------------------------------------------------------------------

def a9_oversize_line_mcp_leg():
    print("\n[A9-mcp] over-64MB line on MCP stdin leg (LIVE: bounded reject, server survives)")
    _rm_lock()
    srv = start_server()
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A9-mcp server up")
        # One line just over the 64 MB MCP_MAX_LINE cap, then a valid initialize.
        # The server rejects the giant line with InvalidData (does not buffer it
        # whole), logs it, and keeps looping -> the later initialize still works.
        huge = "x" * (64 * 1024 * 1024 + 2)
        srv.stdin.write(huge + "\n")
        srv.stdin.flush()
        c = e2e.McpClient(srv)
        c.send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "adv", "version": "0.1"}}})

        def read_until_init():
            for _ in range(12):
                r = c.recv()
                if r.get("id") == 1:
                    return r
            return None

        done, got = _call_with_timeout(read_until_init, 20)
        check(done and got is not None and got.get("result", {}).get("protocolVersion") == "2025-06-18",
              "A9-mcp server survived the >64MB line and still answered initialize")
        check(srv.poll() is None, "A9-mcp server not aborted")
        srv.stdin.close()
        srv.wait(timeout=5)
        err = server_stderr(srv)
        check("exceeds the line-length cap" in err or "parse error" in err,
              "A9-mcp stderr shows a bounded rejection, not a crash")
        check(srv.returncode == 0, "A9-mcp server exited cleanly (no abort signal)")
    finally:
        _reap(srv)


def a9_oversize_frame_nm_leg():
    print("\n[A9-nm] over-64MB native-messaging frame on the host leg (LIVE: bounded reject)")
    if os.name == "nt":
        note("A9-nm skipped: native host leg exercised on Unix")
        return
    _rm_lock()
    srv = start_server()
    nh = None
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A9-nm server up")
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        nh = start_host_from(e2e.BIN)
        check(nh.ready.wait(6), "A9-nm genuine host attested and connected")
        # A ~4 GB length prefix trips the 64 MB inbound clamp in nm_read_frame
        # before any allocation. The host rejects it (InvalidData) and exits;
        # the server is a separate process and must keep serving.
        nh.stdin.write(struct.pack("<I", 0xFFFFFFFF))
        nh.stdin.flush()
        nh.wait(timeout=5)
        check(nh.returncode is not None,
              "A9-nm host rejected the oversize frame and exited (did not OOM)")
        check("frame too large" in host_stderr(nh),
              "A9-nm host logged the bounded native-messaging rejection")
        pong = c.ping(_id=77)
        check(pong.get("result") == {},
              "A9-nm server survived the NM-leg overflow (still answers ping)")
    finally:
        _reap(nh)
        _reap(srv)


# ---------------------------------------------------------------------------
# A11 - no open TCP port: only the UNIX-domain listener exists
# ---------------------------------------------------------------------------

def a11_no_tcp_port():
    print("\n[A11] no open TCP port (LIVE: bridge is a filesystem socket, no network surface)")
    if os.name == "nt":
        note("A11 skipped: Windows intentionally uses a loopback TCP socket")
        return
    _rm_lock()
    srv = start_server()
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A11 server up")
        pid = srv.pid
        sock_name = os.path.basename(lf["endpoint"])  # run.sock
        is_linux = sys.platform.startswith("linux")
        # A11 is a LIVE MUST-BLOCK, so a missing or failed inspection tool is a
        # FAIL, never a silent pass: without a working listener enumerator we
        # cannot assert the negative (no TCP), and an empty stdout from a broken
        # command would make the "no pid" check pass vacuously. We therefore
        # require the tool to exist AND exit 0, and we require the UNIX listener
        # to be POSITIVELY found -- that positive check is what proves the
        # command actually produced meaningful output.
        if is_linux:
            if not check(shutil.which("ss") is not None,
                         "A11 ss present (required on the Linux CI gate)"):
                return
            tcp = subprocess.run(["ss", "-Hltnp"], capture_output=True, text=True)
            unix = subprocess.run(["ss", "-Hlxnp"], capture_output=True, text=True)
            check(tcp.returncode == 0 and unix.returncode == 0,
                  "A11 ss commands succeeded (output is trustworthy)")
            pid_tcp = f"pid={pid}," in tcp.stdout or f"pid={pid})" in tcp.stdout
            pid_unix = f"pid={pid}," in unix.stdout or f"pid={pid})" in unix.stdout
            check(pid_unix,
                  "A11 ss -lxnp POSITIVELY shows the UNIX-domain listener for the server pid")
            check(not pid_tcp,
                  "A11 ss -ltnp shows NO TCP listener owned by the server pid")
        else:  # macOS local: lsof is the equivalent enumerator
            if not check(shutil.which("lsof") is not None,
                         "A11 lsof present (required for the macOS check)"):
                return
            files = subprocess.run(["lsof", "-nP", "-p", str(pid)], capture_output=True, text=True)
            check(files.returncode == 0, "A11 lsof succeeded (output is trustworthy)")
            has_unix = any(sock_name in ln or "\tunix\t" in ln or " unix " in ln
                           for ln in files.stdout.splitlines() if "unix" in ln.lower())
            check(has_unix,
                  "A11 lsof POSITIVELY shows the server holds a UNIX-domain socket")
            has_tcp_listen = any("TCP" in ln and "LISTEN" in ln for ln in files.stdout.splitlines())
            check(not has_tcp_listen, "A11 lsof shows NO TCP LISTEN for the server pid")
            note("A11 macOS path uses lsof; the Linux CI gate uses ss as specified")
    finally:
        _reap(srv)


# ---------------------------------------------------------------------------
# A12 - secret confidentiality: the per-run secret never leaks; doctor redacts
# ---------------------------------------------------------------------------

def a12_secret_confidentiality():
    print("\n[A12] secret confidentiality (LIVE: secret never printed; doctor redacts)")
    if os.name == "nt":
        note("A12 running without attestation round-trip on Windows")
    _rm_lock()
    prev_log = os.environ.get("BB_LOG")
    os.environ["BB_LOG"] = "debug"  # maximum verbosity for the leak hunt
    srv = start_server()
    nh = None
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A12 server up")
        secret = lf["secret"]
        check(len(secret) == 32 and all(ch in "0123456789abcdef" for ch in secret),
              "A12 isolated lock secret is a 32-char hex token")
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        r = None
        if os.name != "nt":
            nh = start_host_from(e2e.BIN)
            if check(nh.ready.wait(6), "A12 verbose attested round-trip established"):
                served = []
                t = threading.Thread(
                    target=lambda: served.append(e2e.serve_bridge_req(nh, _tab_list_responder)))
                t.start()
                r = c.call("tab_list", {}, _id=5)
                t.join(timeout=3)
        _require_isolated()  # doctor reads the lock + probes the socket: keep it isolated
        doc = subprocess.run([e2e.BIN, "doctor"], capture_output=True, text=True)
        _reap(nh)
        srv.stdin.close()
        srv.wait(timeout=5)
        captured = "".join([
            server_stderr(srv),
            host_stderr(nh) if nh is not None else "",
            doc.stdout, doc.stderr,
            json.dumps(r) if r is not None else "",
        ])
        check(secret not in captured,
              "A12 secret NEVER appears in any captured stdout/stderr (server/host/doctor/response)")
        check("<redacted," in doc.stdout and "chars>" in doc.stdout,
              "A12 doctor prints the secret in redacted form")
        check(secret not in doc.stdout, "A12 doctor stdout omits the raw secret")
    finally:
        _reap(nh)
        _reap(srv)
        if prev_log is None:
            os.environ.pop("BB_LOG", None)
        else:
            os.environ["BB_LOG"] = prev_log


# ---------------------------------------------------------------------------
# Annotated / referenced attacks (not re-implemented here)
# ---------------------------------------------------------------------------

def annotated_matrix():
    print("\n[annotated] attacks whose real coverage lives elsewhere")
    note("A4 replay a captured HMAC response: unreachable black-box (dropped at "
         "attestation, A1). MAC/nonce logic proven by src/ipc.rs "
         "verify_mac_accepts_correct_and_rejects_wrong + "
         "handshake_round_trip_over_socketpair.")
    note("A5 forged/garbage MAC: same attestation drop; MAC verification is "
         "constant-time in src/ipc.rs verify_mac (Mac::verify_slice).")
    note("A6 hex-decoder abuse (odd length, non-hex, mid-codepoint UTF-8): "
         "proven by src/ipc.rs hex_decode tests + hex_fuzz::never_panics proptest.")
    note("A7 serde/parser abuse on arbitrary bytes: proven by src/protocol.rs "
         "proptests (nm_read/mcp_read/bridge_read never_panics + size guards).")
    note("A10 cross-uid connect: needs a second uid (root/manual). The 0700 "
         "runtime dir + peer-UID accept check (src/mcp_server.rs) is the gate; "
         "not automatable single-user in CI.")
    note("A13 native-messaging manifest substitution: browser-gated and a "
         "DOCUMENTED RESIDUAL until the enrollment ceremony (task #13) lands. "
         "See a13_manifest_substitution_xfail below.")


# ---------------------------------------------------------------------------
# A14/A15/A16 - trusted-client allowlist admission (Phase 4, ADR-0024)
# ---------------------------------------------------------------------------

def _clients_path():
    return os.path.join(os.path.dirname(e2e.LOCK), "clients.json")


def _revocation_path():
    return os.path.join(os.path.dirname(e2e.LOCK), "revocation.json")


def _rm_clients():
    """Reset the enrollment state between tests: remove clients.json AND the
    revocation record. Removing only clients.json is no longer a reset -- the
    revocation record's enrollment latch turns that into detectable tampering
    (ADR-0025, proven live by A19) -- so a full reset must drop both, which is
    exactly the documented two-file same-user residual."""
    _require_isolated()
    for path in (_clients_path(), _revocation_path()):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def _pair_client(*args):
    """Run `chromium-bridge pair-client ...` under the isolation env. Pairing
    GRANTS harness capability and is presence-gated (ADR-0031), so it is
    driven through the CLI presence floor on a pty (see
    e2e.run_with_cli_presence for the headless-vs-Touch-ID nuance)."""
    _require_isolated()
    e2e.pair_client_interactive(*args)


def _skip_if_enrolled(case):
    """Mirror e2e.py's enrolled-machine guard: the LIVE cases below drive
    pair-client / unkill through the CLI presence floor on a pty, but on a Mac
    with an enrolled Secure Enclave key the presence ladder reaches the
    HARDWARE rung first and would raise a real Touch ID prompt the typed
    phrase cannot satisfy (repo rule: automated tests never raise real
    prompts). e2e.enclave_key_present is fail-safe (indeterminate -> skip)
    and always False off macOS, so Linux/Windows coverage is unaffected. The
    hardware path is covered by `just touchid-gates`."""
    if e2e.enclave_key_present():
        note(f"{case} skipped: real enclave key present, would raise a live prompt")
        return True
    return False


def a14_non_allowlisted_harness_refused():
    print("\n[A14] enrolled + non-allowlisted harness (LIVE, must REFUSE / fail closed)")
    if _skip_if_enrolled("A14"):
        return
    if os.name == "nt":
        note("A14 skipped: harness attestation is Unix-only (Windows secret-only)")
        return
    _rm_lock()
    _rm_clients()
    try:
        # Enroll a DECOY that does not match this python interpreter. Admission
        # is now ENFORCED, so our python-parented server must be refused.
        _pair_client("--name", "decoy", "--hash", "00" * 20)
        srv = start_server()
        try:
            lf = e2e.wait_lock(srv, timeout=3)
            check(lf is None, "A14 refused harness never became the broker (no lock)")
            srv.wait(timeout=5)
            check(srv.returncode == 1, "A14 refused server exits non-zero (fail closed)")
            err = server_stderr(srv)
            check("not in the trusted-client allowlist" in err,
                  "A14 stderr names the allowlist refusal")
        finally:
            _reap(srv)
    finally:
        _rm_clients()


def a15_spoofed_client_name_is_not_authz():
    print("\n[A15] enrolled + spoofed client NAME (LIVE, name is not the authz key)")
    if _skip_if_enrolled("A15"):
        return
    if os.name == "nt":
        note("A15 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    try:
        # Enroll a decoy under the name "trusted". The attacker then claims that
        # exact NAME via the env var. Authorization keys on the attested hash,
        # not the self-asserted name, so admission must still be refused.
        _pair_client("--name", "trusted", "--hash", "11" * 20)
        env = dict(os.environ, CHROMIUM_BRIDGE_CLIENT_NAME="trusted")
        srv = subprocess.Popen([e2e.BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", env=env)
        srv.err_lines = []
        srv.err_thread = threading.Thread(
            target=lambda: [srv.err_lines.append(ln) for ln in srv.stderr], daemon=True)
        srv.err_thread.start()
        try:
            lf = e2e.wait_lock(srv, timeout=3)
            check(lf is None, "A15 a matching NAME does not admit a non-matching hash")
            srv.wait(timeout=5)
            check(srv.returncode == 1, "A15 refused despite the spoofed name (fail closed)")
        finally:
            _reap(srv)
    finally:
        _rm_clients()


def a16_paired_harness_is_admitted():
    print("\n[A16] enrolled + genuinely paired harness (LIVE, must be ADMITTED and serve)")
    if _skip_if_enrolled("A16"):
        return
    if os.name == "nt":
        note("A16 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    nh = None
    srv = None
    try:
        # Pair THIS python (the server's parent) by its real attested identity.
        # A server it spawns must now be admitted -- enrollment must not brick a
        # genuinely trusted client, and the allowlist gates on the real hash.
        _pair_client("--name", "pytest", "--this-parent")
        srv = start_server()
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A16 paired harness IS admitted and becomes the broker")
        if lf is None:
            return
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        nh = e2e.start_bridge_host()
        e2e.wait_host_ready(nh)
        served = []
        t = threading.Thread(
            target=lambda: served.append(e2e.serve_bridge_req(nh, _tab_list_responder)))
        t.start()
        r = c.call("tab_list", {}, _id=42)
        t.join(timeout=3)
        check(bool(served), "A16 a tool call round-trips through the admitted broker")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "Adversarial Tab",
              "A16 the paired client actually drives the browser")
    finally:
        if nh is not None and nh.poll() is None:
            nh.kill()
            try:
                nh.wait(timeout=3)
            except Exception:
                pass
        _reap(srv)
        _rm_clients()


# ---------------------------------------------------------------------------
# A17/A18/A19 - any-side revocation epoch (Phase 5, ADR-0025)
# ---------------------------------------------------------------------------

def _read_revocation():
    with open(_revocation_path()) as f:
        return json.load(f)


def a17_revoke_reaches_the_live_broker():
    print("\n[A17] revoke-client vs a LIVE broker (LIVE: dropped + no re-attach)")
    if _skip_if_enrolled("A17"):
        return
    if os.name == "nt":
        note("A17 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    srv = None
    nh = None
    try:
        # Pair this python and stand up a serving broker (the A16 shape).
        _pair_client("--name", "pytest", "--this-parent")
        srv = start_server()
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A17 paired harness is admitted and becomes the broker")
        if lf is None:
            return
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        nh = e2e.start_bridge_host()
        e2e.wait_host_ready(nh)
        served = []
        t = threading.Thread(
            target=lambda: served.append(e2e.serve_bridge_req(nh, _tab_list_responder)))
        t.start()
        c.call("tab_list", {}, _id=50)
        t.join(timeout=3)
        check(bool(served), "A17 the paired client drives the bridge before the revoke")

        # Revoke from the CLI surface. The allowlist rewrite and the epoch
        # bump land in one critical section (ADR-0025).
        subprocess.run([e2e.BIN, "revoke-client", "--name", "pytest"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rev = _read_revocation()
        check(rev["epoch"] > 0 and rev["clients_epoch"] == rev["epoch"],
              "A17 the revocation epoch was bumped with the clients marker")

        # The live broker must refuse the next request: the per-request epoch
        # guard re-decides against the fresh allowlist and drops the (own)
        # harness. Observed as EOF on the server's stdout, never a response.
        c.send({"jsonrpc": "2.0", "id": 51, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        finished, line = _call_with_timeout(lambda: srv.stdout.readline(), 10)
        check(finished and line == "",
              "A17 the revoked harness's next call gets EOF (fail closed), not service")
        srv.wait(timeout=5)
        check(srv.returncode is not None, "A17 the broker for the revoked harness exits")

        # Re-attach is refused immediately: a fresh instance spawned by the
        # same (now revoked) harness must fail closed, not become a broker.
        srv2 = start_server()
        try:
            lf2 = e2e.wait_lock(srv2, timeout=3)
            check(lf2 is None, "A17 a revoked client cannot re-attach or rebind")
            srv2.wait(timeout=5)
            check(srv2.returncode == 1, "A17 re-attach fails closed (exit 1)")
            check("not in the trusted-client allowlist" in server_stderr(srv2),
                  "A17 stderr names the allowlist refusal")
        finally:
            _reap(srv2)
    finally:
        if nh is not None and nh.poll() is None:
            nh.kill()
            try:
                nh.wait(timeout=3)
            except Exception:
                pass
        _reap(srv)
        _rm_clients()


def a18_extension_surface_revoke_via_host_control_frames():
    print("\n[A18] extension-surface revoke (LIVE: client_revoke via the native host)")
    if _skip_if_enrolled("A18"):
        return
    if os.name == "nt":
        note("A18 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    srv = None
    nh = None
    try:
        # Two trusted clients: this python, and a victim entry the "extension"
        # will revoke through the host-handled admin control frames.
        _pair_client("--name", "pytest", "--this-parent")
        _pair_client("--name", "victim", "--hash", "22" * 32)
        srv = start_server()
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A18 broker up with two trusted clients")
        if lf is None:
            return
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        nh = e2e.start_bridge_host()
        e2e.wait_host_ready(nh)

        # client_list is answered by the HOST itself, never forwarded.
        e2e.nm_write(nh, {"type": "client_list"})
        reply = e2e.nm_read(nh)
        check(reply is not None and reply.get("type") == "client_list_result"
              and reply.get("ok") is True and reply.get("enrolled") is True,
              "A18 client_list answered locally with the enrolled list")
        names = sorted(cl["name"] for cl in reply.get("clients", []))
        check(names == ["pytest", "victim"], "A18 the list names both trusted clients")

        # Revoke the victim from the extension surface.
        before = _read_revocation()["epoch"]
        e2e.nm_write(nh, {"type": "client_revoke", "name": "victim"})
        reply = e2e.nm_read(nh)
        check(reply is not None and reply.get("type") == "client_revoke_result"
              and reply.get("ok") is True,
              "A18 client_revoke acknowledged ok")
        with open(_clients_path()) as f:
            names = [cl["name"] for cl in json.load(f)["clients"]]
        check(names == ["pytest"], "A18 the allowlist no longer contains the victim")
        check(_read_revocation()["epoch"] > before,
              "A18 the revocation epoch was bumped by the host-mediated revoke")

        # The surviving trusted client still drives the bridge: the revoke
        # reached enforcement without collateral damage.
        served = []
        t = threading.Thread(
            target=lambda: served.append(e2e.serve_bridge_req(nh, _tab_list_responder)))
        t.start()
        r = c.call("tab_list", {}, _id=60)
        t.join(timeout=3)
        check(bool(served), "A18 the still-trusted client keeps serving after the revoke")
        content = json.loads(r["result"]["content"][0]["text"])
        check(content[0]["title"] == "Adversarial Tab", "A18 round trip intact")

        # Revoking a ghost fails cleanly with ok:false, never a guess.
        e2e.nm_write(nh, {"type": "client_revoke", "name": "ghost"})
        reply = e2e.nm_read(nh)
        check(reply is not None and reply.get("type") == "client_revoke_result"
              and reply.get("ok") is False,
              "A18 revoking an unknown client reports ok:false")
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
        _reap(srv)
        _rm_clients()


def a19_deleting_the_allowlist_is_tampering_not_a_reset():
    print("\n[A19] clients.json deletion (LIVE: detected via the enrollment latch)")
    if _skip_if_enrolled("A19"):
        return
    if os.name == "nt":
        note("A19 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    try:
        # Enroll, then simulate the ADR-0024 residual: a same-user deletion of
        # clients.json alone. Pre-Phase-5 this silently reverted the bridge to
        # the open, unenrolled bootstrap; the revocation record's enrollment
        # latch (ADR-0025) must now fail it closed instead.
        _pair_client("--name", "pytest", "--this-parent")
        os.remove(_clients_path())
        srv = start_server()
        try:
            lf = e2e.wait_lock(srv, timeout=3)
            check(lf is None, "A19 deletion does not revert to the open bootstrap")
            srv.wait(timeout=5)
            check(srv.returncode == 1, "A19 the server fails closed (exit 1)")
            err = server_stderr(srv)
            check("tampering" in err,
                  "A19 stderr names the deletion as tampering")
        finally:
            _reap(srv)

        # Residual, named honestly and pinned by this check: deleting BOTH
        # files (the allowlist and the revocation record) is the full
        # same-user revert to bootstrap. No user-space marker survives a
        # writer who can delete any file we can write; see ADR-0025.
        _rm_clients()
        srv = start_server()
        try:
            lf = e2e.wait_lock(srv, timeout=5)
            check(lf is not None,
                  "A19 two-file deletion reverts to the unenrolled bootstrap "
                  "(the documented same-user residual)")
            err_seen = any("harness admission is NOT enforced" in ln
                           for ln in srv.err_lines)
            check(err_seen, "A19 the bootstrap posture is ERROR-logged, not silent")
        finally:
            _reap(srv)
    finally:
        _rm_clients()


def a20_kill_reaches_every_enforcement_point():
    """ADR-0030: with a PAIRED, admitted, actively-driving client, engaging the
    kill switch must (1) turn the live broker's dispatch into typed
    BRIDGE_KILLED refusals without dropping the harness (the refusal must be
    deliverable), (2) sever the connected browser leg, (3) keep a fresh host
    off the bridge entirely (control-plane only), and (4) refuse tool calls
    from a freshly attached RELAY too (the second-instance path shares the
    dispatcher). Note on the broker's browser-attach refusal: it is not
    black-box reachable here, because the host itself refuses to dial while
    killed (the layers are redundant by design); it is pinned by code review
    and the broker unit tests."""
    print("\n[A20] kill switch vs a LIVE broker (LIVE: typed refusal at every surface)")
    if _skip_if_enrolled("A20"):
        return
    if os.name == "nt":
        note("A20 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    srv = None
    srv2 = None
    nh = None
    nh2 = None
    try:
        _pair_client("--name", "pytest", "--this-parent")
        srv = start_server()
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A20 paired harness becomes the broker")
        if lf is None:
            return
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        nh = e2e.start_bridge_host()
        e2e.wait_host_ready(nh)
        served = []
        t = threading.Thread(
            target=lambda: served.append(e2e.serve_bridge_req(nh, _tab_list_responder)))
        t.start()
        c.call("tab_list", {}, _id=60)
        t.join(timeout=3)
        check(bool(served), "A20 the bridge works before the kill")

        subprocess.run([e2e.BIN, "kill"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rev = _read_revocation()
        check(rev["killed"] is True and rev["kill_epoch"] == rev["epoch"],
              "A20 the kill landed with its epoch bump in one record")

        # (1) The live broker refuses with the stable code and KEEPS the
        # harness connection up (a response arrives; no EOF).
        r = c.call("tab_list", {}, _id=61)
        text = r["result"]["content"][0]["text"]
        check(r["result"].get("isError") is True and "BRIDGE_KILLED" in text,
              "A20 dispatch refuses with the typed BRIDGE_KILLED error")
        r = c.ping(_id=62)
        check("result" in r, "A20 the harness connection survives to carry refusals")

        # (2) The browser leg is severed within a watcher tick. Keep the
        # handle either way: the finally block only kills a still-running
        # host, so a failed severing is cleaned up, not leaked.
        try:
            nh.wait(timeout=8)
        except Exception:
            pass
        check(nh.poll() is not None, "A20 the connected browser host is severed")

        # (3) A fresh host never reaches the bridge while killed.
        nh2 = e2e.start_bridge_host()
        frame = e2e.nm_read(nh2)
        check(frame is not None and frame.get("type") == "kill_status_result"
              and frame.get("killed") is True,
              "A20 a fresh host is control-plane only (announces killed)")
        check(not nh2.ready.is_set(), "A20 the fresh host never handshakes the bridge")

        # (4) A relay (second instance) attaches -- admission is a revocation
        # decision, not a kill decision -- but its calls are refused the same
        # typed way by the shared dispatcher.
        srv2 = start_server()
        c2 = e2e.McpClient(srv2)
        c2.initialize()
        c2.initialized()
        r = c2.call("tab_list", {}, _id=63)
        text = r["result"]["content"][0]["text"]
        check(r["result"].get("isError") is True and "BRIDGE_KILLED" in text,
              "A20 a relayed harness gets the same typed refusal")
    finally:
        for host in (nh, nh2):
            if host is not None and host.poll() is None:
                host.kill()
                try:
                    host.wait(timeout=3)
                except Exception:
                    pass
        _reap(srv2)
        _reap(srv)
        e2e.unkill_interactive(check=False)
        _rm_clients()


def a21_corrupt_kill_marker_fails_closed():
    """ADR-0030: with the revocation record corrupt, the kill/latch state is
    unknowable, and EVERYTHING must fail closed: a live broker drops its
    harness (the per-request guard reads the record first), a fresh instance
    refuses to start, `unkill` refuses (releasing from an unknown state would
    fail open) while the attempt still lands in the audit trail
    (outcome=error, with the auth rung that passed), and `doctor` reports the
    unreadable state non-zero."""
    print("\n[A21] corrupt revocation record (LIVE: kill state unknown -> refuse everything)")
    if _skip_if_enrolled("A21"):
        return
    if os.name == "nt":
        note("A21 skipped: harness attestation is Unix-only")
        return
    _rm_lock()
    _rm_clients()
    srv = None
    try:
        _pair_client("--name", "pytest", "--this-parent")
        srv = start_server()
        lf = e2e.wait_lock(srv)
        check(lf is not None, "A21 broker up before the corruption")
        if lf is None:
            return
        c = e2e.McpClient(srv)
        c.initialize()
        c.initialized()
        # Drain the pipe before corrupting: the guard runs on EVERY inbound
        # message, and `initialized` is fire-and-forget, so corrupting while
        # it is still unprocessed drops the connection before the tools/call
        # below is even written (a BrokenPipeError instead of the EOF).
        c.ping(_id=69)

        with open(_revocation_path(), "w") as f:
            f.write("{ this is not json")

        # The live broker: the per-request guard reads the record before any
        # dispatch and fails the connection closed (EOF, no service).
        c.send({"jsonrpc": "2.0", "id": 70, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        finished, line = _call_with_timeout(lambda: srv.stdout.readline(), 10)
        check(finished and line == "",
              "A21 the live broker drops the harness on an unreadable record")

        # A fresh instance refuses to serve at all.
        srv2 = start_server()
        try:
            lf2 = e2e.wait_lock(srv2, timeout=3)
            check(lf2 is None, "A21 a fresh instance refuses to start")
            srv2.wait(timeout=5)
            check(srv2.returncode == 1, "A21 the refusal is fail-closed (exit 1)")
        finally:
            _reap(srv2)

        # unkill refuses: releasing from an unknown state would fail open.
        # Driven interactively (pty + the exact phrase), so the refusal being
        # tested is the unreadable RECORD, not the presence floor.
        unkill = e2e.unkill_interactive(check=False)
        check(unkill.returncode == 1 and "fail open" in unkill.stderr,
              "A21 `unkill` refuses on an unreadable record")

        # The presence-passing-but-write-refused attempt is DURABLY audited
        # (ADR-0030: every release attempt leaves a trace), with the error
        # outcome and the auth rung that vouched for it. The audit file is
        # separate from the corrupt revocation record, so the trail survives.
        audit_path = os.path.join(os.path.dirname(e2e.LOCK), "audit.log")
        records = []
        with open(audit_path) as f:
            records = [json.loads(ln) for ln in f if ln.strip()]
        errored = [r for r in records if r.get("kind") == "kill_release"
                   and r.get("outcome") == "error"]
        check(bool(errored),
              "A21 the errored-after-presence release attempt is audited")
        detail = errored[-1].get("detail", "")
        check("auth=cli_confirm" in detail and "write refused" in detail,
              "A21 the errored release names its auth rung and the write error")

        # doctor reports it, non-zero.
        doc = subprocess.run([e2e.BIN, "doctor"], capture_output=True, text=True)
        check(doc.returncode == 1 and "UNREADABLE" in doc.stdout,
              "A21 `doctor` surfaces the unreadable kill state")
    finally:
        _reap(srv)
        _rm_clients()


def a22_unkill_requires_interactive_user_presence():
    """ADR-0030: releasing the kill switch requires the user-presence floor.
    A piped stdin - a script, a harness, any other program - is refused even
    with the exact phrase on it, so no same-user process can reopen the
    bridge SILENTLY through the CLI; an interactive session that types the
    wrong phrase is refused; the switch stays engaged through both refusals,
    each of which lands in the audit trail with its presence reason; and the
    typed phrase on a real terminal is what finally releases, audited with
    auth=cli_confirm. (The remaining non-interactive path, editing
    revocation.json directly, is the conceded same-user residual; Touch ID
    hardware replaces this floor in Phase 8.)"""
    print("\n[A22] unkill demands user presence (LIVE: piped/declined refused, typed releases)")
    if _skip_if_enrolled("A22"):
        return
    if os.name == "nt":
        note("A22 skipped: the pty-driven confirmation is Unix-only")
        return
    _rm_lock()
    audit_path = os.path.join(os.path.dirname(e2e.LOCK), "audit.log")
    try:
        os.remove(audit_path)
    except FileNotFoundError:
        pass
    try:
        subprocess.run([e2e.BIN, "kill"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check(_read_revocation()["killed"] is True, "A22 the switch is engaged")

        # (1) A piped stdin is refused outright, exact phrase and all.
        piped = subprocess.run([e2e.BIN, "unkill"], input="release\n",
                               capture_output=True, text=True)
        check(piped.returncode == 1 and "not a terminal" in piped.stderr,
              "A22 a piped `unkill` is refused (no silent script release)")
        check(_read_revocation()["killed"] is True,
              "A22 the switch stays engaged after the piped attempt")

        # (2) An interactive session typing the wrong phrase is refused.
        wrong = e2e.unkill_interactive(phrase="yes", check=False)
        check(wrong.returncode == 1, "A22 the wrong phrase is refused")
        check(_read_revocation()["killed"] is True,
              "A22 the switch stays engaged after the declined prompt")

        # (3) Both refusals are visible in the trail, with their reasons.
        with open(audit_path) as f:
            records = [json.loads(ln) for ln in f if ln.strip()]
        refused = [r for r in records if r.get("kind") == "kill_release"
                   and r.get("outcome") == "refused"]
        check(len(refused) == 2, "A22 both refused releases are audited")
        details = " | ".join(r.get("detail", "") for r in refused)
        check("presence" in details,
              "A22 the refusals name the presence gate that stopped them")

        # (4) The typed phrase on a real terminal releases, and the audit
        # record names the rung that authorized it.
        ok = e2e.unkill_interactive()
        check(ok.returncode == 0, "A22 the typed confirmation releases")
        check(_read_revocation()["killed"] is False, "A22 the switch is off")
        with open(audit_path) as f:
            records = [json.loads(ln) for ln in f if ln.strip()]
        released = [r for r in records if r.get("kind") == "kill_release"
                    and r.get("outcome") == "ok"]
        check(bool(released) and "auth=cli_confirm" in released[-1].get("detail", ""),
              "A22 the release is audited with auth=cli_confirm")
    finally:
        e2e.unkill_interactive(check=False)


def a13_manifest_substitution_xfail():
    print("\n[A13] native-messaging manifest substitution (XFAIL until enrollment #13)")
    # A malicious install could point the NM manifest at a different host binary,
    # or add its own extension id to the allowed_origins. Today nothing but the
    # 0700 install dir stops a same-user rewrite of the manifest, and proving the
    # end-to-end effect needs a real (isolated) browser loading the extension.
    # This flips from XFAIL to a LIVE MUST-BLOCK once enrollment (#13) makes the
    # extension pin the host's enclave key, so a substituted manifest/host cannot
    # complete the mutual key exchange.
    # TODO(#13): implement against an ISOLATED throwaway browser profile after
    # enrollment lands; assert a substituted host fails the enclave handshake.
    note("A13 intentionally not implemented here (browser + enrollment gated). "
         "Documented residual; becomes MUST-BLOCK after task #13.")


# ---------------------------------------------------------------------------

def main():
    if os.name == "nt":
        print("adversarial suite targets the Unix attestation surface; "
              "most checks are Unix-only.")
    e2e.ensure_binary()          # build with the real environment if needed
    rundir = isolate()           # then lock every subprocess into the private dir
    print(f"binary: {e2e.BIN}")
    print(f"platform: {platform.system()} {platform.machine()}")
    try:
        a1_rogue_python_peer()
        a2_same_binary_copy()
        a3_binary_swap_after_launch()
        a8_blank_line_flood()
        a9_oversize_line_mcp_leg()
        a9_oversize_frame_nm_leg()
        a11_no_tcp_port()
        a12_secret_confidentiality()
        a14_non_allowlisted_harness_refused()
        a15_spoofed_client_name_is_not_authz()
        a16_paired_harness_is_admitted()
        a17_revoke_reaches_the_live_broker()
        a18_extension_surface_revoke_via_host_control_frames()
        a19_deleting_the_allowlist_is_tampering_not_a_reset()
        a20_kill_reaches_every_enforcement_point()
        a21_corrupt_kill_marker_fails_closed()
        a22_unkill_requires_interactive_user_presence()
        annotated_matrix()
        a13_manifest_substitution_xfail()
    finally:
        shutil.rmtree(rundir, ignore_errors=True)
    print(f"\n{'=' * 44}\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
