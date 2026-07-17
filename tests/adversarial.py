#!/usr/bin/env python3
"""Adversarial break-in regression suite for browser-bridge.

This is the socket-level attacker's view of the bridge. It drives the real
release binary as subprocesses (reusing tests/e2e.py's harness) and tries to
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
    python3 tests/adversarial.py
Exits 0 when every LIVE MUST-BLOCK check passes, 1 otherwise. Builds the
release binary via tests/e2e.py's ensure_binary if missing.
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
    # The lock lives at <XDG_RUNTIME_DIR>/browser-bridge/run.lock on every unix
    # (src/ipc.rs runtime_dir). Recompute it and steer e2e's helpers at it.
    lock = os.path.join(rundir, "browser-bridge", "run.lock")
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
        # A raw python process is not the browser-bridge binary. Server-side
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
        annotated_matrix()
        a13_manifest_substitution_xfail()
    finally:
        shutil.rmtree(rundir, ignore_errors=True)
    print(f"\n{'=' * 44}\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
