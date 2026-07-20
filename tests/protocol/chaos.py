#!/usr/bin/env python3
"""Fault-injection / chaos suite for chromium-bridge's runtime paths.

The mock e2e suite drives the happy path: every peer behaves, every frame is
whole, every process exits on cue. Real bugs hide in the OTHER paths - a peer
that vanishes mid-frame, a truncated length prefix at a process boundary, a
storm of reconnects, a server SIGKILLed with a request in flight. A real
takeover bug (the socket unlinked out from under a freshly-bound listener)
lived in exactly this territory. This suite injects those faults against the
real release binary and asserts the invariant every time: the server stays
healthy or fails CLOSED and RECOVERS - no hang, no fd/process leak, no
corruption, no panic.

What is proven here (socket/process level, runnable in CI) vs what is only
noted (browser-gated, needs an isolated Chrome):

  C1  abrupt socket drop with a request in flight   LIVE  server recovers
  C2  truncated native-messaging frame at the host  LIVE  clean reject, alive
  C3  reconnect storm (many hosts)                   LIVE  healthy, no fd leak
  C4  concurrent server starts settle to one owner   LIVE  one reachable bridge
  C5  server SIGKILLed mid-request                    LIVE  client EOF, recovers
  C6  peer death in the connect/handshake window      LIVE  no stale slot, alive
  C7  stale lock+socket from an ungraceful exit       LIVE  next server rebinds
  C8  service-worker death mid-op / MV3 reconnect     SKIP  browser-gated (TODO)

Honesty about C1: only another instance of THIS binary passes peer attestation
(ADR-0020), so a black-box test cannot write literal half-a-line bridge bytes
onto the socket from a foreign process - that path is unreachable to an
attacker and is covered by the Rust parser proptests (src/protocol.rs
bridge_read_never_panics + the cap/blank-line unit tests). What C1 injects at
the integration level is the observable-equivalent fault: an attested peer that
drops the connection abruptly (SIGKILL) while the server has a request
outstanding to it. That is the recovery path the takeover bug broke.

Honesty about C6: killing a real (attested) native host squarely BETWEEN the
handshake's first and last byte is inherently racy - the handshake over a local
socket is a few microseconds. So C6 does not claim to interrupt the HMAC
exchange at a fixed byte. It proves the server-side invariant that actually
matters and holds for EVERY interleaving: a peer that the server accepted and
began processing, then lost (before OR after the handshake completed), never
leaves a stale registry slot and never wedges the accept loop. It anchors that
with a DETERMINISTIC sub-case (a foreign peer that connects and vanishes, which
the server must reject at attestation and forget) and a racy sub-case (real
hosts killed the instant they report a completed socket connect, i.e. inside
the attestation+handshake window). Both assert the same end state.

C4 is deliberately stronger than e2e's single concurrent-start check: more
servers, repeated rounds, and the winner's socket must actually round-trip a
real native-host handshake + tool call, not merely exist on disk. It asserts
LIVENESS / one-owner only; the PID-attestation-before-SIGTERM safety of
takeover (PID reuse) is owned by task #35's suite and is NOT duplicated here.

SAFETY (load-bearing, identical to adversarial.py): every subprocess runs
inside a per-run mkdtemp XDG_RUNTIME_DIR (+ XDG_CONFIG_HOME, + HOME on macOS)
so the server's lock, socket, and takeover logic can NEVER touch the
developer's real MCP server, runtime dir, or browser. We reuse
adversarial.isolate()/_require_isolated() verbatim: isolation is asserted as a
hard precondition and re-checked before every spawn; the suite REFUSES to run
otherwise. This file never launches a browser and never touches CHROME_BIN.

Every blocking read here (a forwarded frame off a host, an MCP response, an
initialize/ping) runs under a hard timeout via adversarial._call_with_timeout,
so a fault-path REGRESSION surfaces as a failed check, never a hung CI job.

Run:
    python3 tests/protocol/chaos.py
Exits 0 when every LIVE scenario passes, 1 otherwise. Builds the release binary
via e2e.ensure_binary if missing (a stale binary silently tests old code - the
caller should `cargo build --release` first).
"""
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402  (path set above; reuse the e2e harness verbatim)
import adversarial as adv  # noqa: E402  (reuse its mandatory XDG isolation)

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


def skip(label):
    print(f"  SKIP  {label}")


# ---------------------------------------------------------------------------
# Bounded blocking reads: a hang is a FAILED check, never a hung gate
# ---------------------------------------------------------------------------

def bounded(label, fn, secs=20):
    """Run `fn` under a hard timeout on a daemon thread. Returns its value, or
    None after recording a FAIL if it did not finish in `secs` - so a fault-path
    regression that stops the server responding fails the check promptly instead
    of blocking the required CI gate forever. Exceptions from `fn` propagate
    (callers that expect an exception, e.g. C5's EOF read, catch it inside)."""
    done, val = adv._call_with_timeout(fn, secs)
    if not done:
        check(False, f"{label} did not complete within {secs}s (hang = fail, not a stuck gate)")
        return None
    return val


# ---------------------------------------------------------------------------
# Spawn helpers (isolation-guarded, reusing adversarial's precondition)
# ---------------------------------------------------------------------------

# Stderr markers the native host logs on its way up (src/native_host.rs). The
# "connected" marker fires after the socket connect (so the server has ACCEPTED
# the connection) but before the handshake completes; "ready" fires once the
# handshake completes.
_HOST_CONNECTED = b"connected to MCP server bridge socket"
_HOST_READY = b"bridge handshake complete"


def start_host(label=None):
    """Spawn `chromium-bridge --native-host` the way Chrome does, in binary mode
    (native-messaging framing is raw bytes). Isolation-guarded via adversarial's
    precondition so it can never dial the developer's real socket. Sets
    `nh.connected` when the host logs the post-connect marker and `nh.ready` when
    the handshake completes, and keeps stderr lines for assertions. The drain
    thread handle is stored on `nh` so cleanup can join it before closing pipes
    (no I/O-on-closed-file noise from a still-running reader)."""
    adv._require_isolated()
    cmd = [e2e.BIN, "--native-host"]
    if label is not None:
        cmd += ["--label", label]
    nh = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    nh.ready = threading.Event()
    nh.connected = threading.Event()
    nh.err_lines = []

    def drain():
        for line in nh.stderr:
            nh.err_lines.append(line)
            if _HOST_CONNECTED in line:
                nh.connected.set()
            if _HOST_READY in line:
                nh.ready.set()

    nh._drain = threading.Thread(target=drain, daemon=True)
    nh._drain.start()
    return nh


def wait_ready(nh, timeout=10):
    """Block until the host completes its bridge handshake, or return False."""
    return nh.ready.wait(timeout)


def sigkill(proc):
    """Abrupt, uncatchable termination of a process WE started (never a
    pattern-matched kill - a specific PID we own). Simulates an ungraceful
    crash: no signal handler runs, no cleanup happens."""
    if proc is None:
        return
    if proc.poll() is None:
        proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


def close_host(nh):
    """SIGKILL a host and fully release its pipes so the harness itself does not
    leak fds across a storm of reconnects (three pipes per host). Joins the
    stderr drain thread first: after the kill the pipe hits EOF and the thread
    exits, so closing afterward is quiet."""
    if nh is None:
        return
    sigkill(nh)
    drain = getattr(nh, "_drain", None)
    if drain is not None:
        drain.join(timeout=2)
    for p in (nh.stdin, nh.stdout, nh.stderr):
        try:
            if p is not None:
                p.close()
        except Exception:
            pass


def host_stderr(nh):
    return b"".join(nh.err_lines).decode("utf-8", "replace")


def count_fds(pid):
    """Open-file-descriptor count for `pid`, or None if it cannot be measured.
    Linux reads /proc/<pid>/fd directly; macOS falls back to `lsof -p`. Used by
    the reconnect-storm test to prove the server does not leak a descriptor per
    dropped connection. Returns None (not 0) when unmeasurable so the caller can
    FAIL rather than pass vacuously."""
    if sys.platform.startswith("linux"):
        try:
            return len(os.listdir(f"/proc/{pid}/fd"))
        except OSError:
            return None
    try:
        out = subprocess.run(["lsof", "-nP", "-p", str(pid)],
                             capture_output=True, text=True, timeout=20)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
    if lines and lines[0].startswith("COMMAND"):
        lines = lines[1:]
    return len(lines)


def mcp_ready(srv, secs=20):
    """Bring an MCP client to the initialized state over `srv`'s stdio, under a
    timeout so a wedged server fails the check instead of hanging."""
    c = e2e.McpClient(srv)

    def init():
        c.initialize()
        c.initialized()
        return True

    if bounded("MCP initialize", init, secs) is None:
        check(False, "MCP server reached the initialized state")
    return c


def round_trip_ok(c, nh, title="Chaos OK", browser=None, _id=900, secs=30):
    """Drive one tab_list call end to end through a connected host and return
    True iff the host's data came back. The call runs under a timeout: a wedged
    server yields False (a failed check), never a hang. The host must already be
    ready."""
    def responder(req):
        return {"id": req["id"], "ok": True,
                "data": [{"id": 1, "title": title, "url": "https://x", "active": True}]}

    served = []
    t = threading.Thread(target=lambda: served.append(e2e.serve_bridge_req(nh, responder)))
    t.start()
    args = {"browser": browser} if browser else {}
    r = bounded(f"round-trip {title}", lambda: c.call("tab_list", args, _id=_id), secs)
    t.join(timeout=5)
    if r is None:
        return False
    try:
        data = json.loads(r["result"]["content"][0]["text"])
        return bool(served) and data and data[0]["title"] == title
    except Exception:
        return False


# ---------------------------------------------------------------------------
# C1 - abrupt socket drop with a request in flight -> server recovers
# ---------------------------------------------------------------------------

def c1_abrupt_drop_mid_request():
    print("\n[C1] abrupt socket drop with a request in flight (LIVE: recover, no hang)")
    if os.name == "nt":
        skip("C1 targets the Unix attested-peer drop path")
        return
    adv._rm_lock()
    srv = adv.start_server()
    nh = None
    try:
        check(e2e.wait_lock(srv) is not None, "C1 server up, lock written")
        c = mcp_ready(srv)
        nh = start_host()
        if not check(wait_ready(nh), "C1 host attested and connected"):
            return

        # Issue a tool call on a background thread. The server forwards a
        # BridgeReq to the host and then blocks waiting for the response.
        box = {}
        caller = threading.Thread(
            target=lambda: box.__setitem__("r", c.call("tab_list", {}, _id=41)))
        caller.start()

        # Confirm the request is actually in flight at the host (it arrived as
        # an NM frame on the host's stdout) BEFORE we drop the connection - so
        # the drop is genuinely mid-request, not before dispatch. Bounded so a
        # server that never forwards fails here rather than hanging.
        req = bounded("C1 in-flight frame read", lambda: e2e.nm_read(nh), 15)
        check(req is not None and req.get("op") == "tab_list",
              "C1 request reached the host (in flight)")

        # Abruptly kill the host WITHOUT answering: the server's reader sees a
        # socket EOF and must fail the in-flight caller fast (Disconnected),
        # not hang it for the full 120s response timeout.
        sigkill(nh)
        caller.join(timeout=20)
        check(not caller.is_alive(), "C1 in-flight call returned promptly (no 120s hang)")
        r = box.get("r")
        check(r is not None and r.get("result", {}).get("isError") is True,
              "C1 in-flight call failed closed with isError (clean error, not corruption)")
        check(srv.poll() is None, "C1 server process survived the abrupt drop")

        # Recovery: a fresh host connects against the SAME live server and a
        # new tool call round-trips. This is the leg the takeover bug broke.
        nh2 = start_host()
        try:
            if check(wait_ready(nh2), "C1 a fresh host reconnects to the same server"):
                check(round_trip_ok(c, nh2, title="C1 Recovered", _id=42),
                      "C1 tool call round-trips after recovery")
        finally:
            close_host(nh2)
    finally:
        adv._reap(nh)
        adv._reap(srv)


# ---------------------------------------------------------------------------
# C2 - truncated native-messaging frame at the process boundary
# ---------------------------------------------------------------------------

def c2_truncated_nm_frame():
    print("\n[C2] truncated native-messaging frame at the host boundary (LIVE: clean reject)")
    if os.name == "nt":
        skip("C2 exercises the Unix native-host leg")
        return

    # (a) A partial 4-byte length prefix (2 of 4 bytes) then EOF. nm_read_frame
    # reads the header with read_exact; a short read at a frame boundary is the
    # canonical EOF (Ok(None)) and the host shuts down cleanly (exit 0).
    adv._rm_lock()
    srv = adv.start_server()
    nh = None
    try:
        check(e2e.wait_lock(srv) is not None, "C2(a) server up")
        c = mcp_ready(srv)
        nh = start_host()
        if check(wait_ready(nh), "C2(a) host connected"):
            nh.stdin.write(b"\x02\x00")  # 2 bytes of a 4-byte length prefix
            nh.stdin.flush()
            nh.stdin.close()
            nh.wait(timeout=5)
            check(nh.returncode is not None, "C2(a) host exited on the partial prefix (no hang)")
            check(nh.returncode == 0, "C2(a) partial prefix is a clean EOF shutdown (exit 0)")
            check(srv.poll() is None, "C2(a) server survived")
            pong = bounded("C2(a) ping", lambda: c.ping(_id=201), 15)
            check(pong is not None and pong.get("result") == {}, "C2(a) server still answers ping")
    finally:
        adv._reap(nh)
        adv._reap(srv)

    # (b) A full length prefix promising N bytes, but only a couple of body
    # bytes then EOF. read_exact of the body fails with UnexpectedEof, which is
    # a hard error (not the clean frame-boundary EOF): the host logs it and
    # exits, and the server keeps serving.
    adv._rm_lock()
    srv = adv.start_server()
    nh = None
    try:
        check(e2e.wait_lock(srv) is not None, "C2(b) server up")
        c = mcp_ready(srv)
        nh = start_host()
        if check(wait_ready(nh), "C2(b) host connected"):
            nh.stdin.write(struct.pack("<I", 4096) + b"{\"")  # promise 4096, send 2
            nh.stdin.flush()
            nh.stdin.close()
            nh.wait(timeout=5)
            check(nh.returncode is not None, "C2(b) host exited on the truncated body (no hang)")
            check("stdin read error" in host_stderr(nh),
                  "C2(b) host logged the truncated-frame read error (fail closed)")
            check(srv.poll() is None, "C2(b) server survived the truncated frame")
            pong = bounded("C2(b) ping", lambda: c.ping(_id=202), 15)
            check(pong is not None and pong.get("result") == {}, "C2(b) server still answers ping")

            # And the server can still take a fresh, well-behaved host.
            nh2 = start_host()
            try:
                if check(wait_ready(nh2), "C2(b) a fresh host connects afterward"):
                    check(round_trip_ok(c, nh2, title="C2 OK", _id=203),
                          "C2(b) tool call round-trips after the truncated-frame reject")
            finally:
                close_host(nh2)
    finally:
        adv._reap(nh)
        adv._reap(srv)


# ---------------------------------------------------------------------------
# C3 - reconnect storm: many hosts connect/disconnect -> healthy, no fd leak
# ---------------------------------------------------------------------------

def c3_reconnect_storm():
    print("\n[C3] reconnect storm (LIVE: server healthy, no fd leak)")
    if os.name == "nt":
        skip("C3 relies on Unix fd inspection (/proc or lsof)")
        return
    adv._rm_lock()
    srv = adv.start_server()
    try:
        check(e2e.wait_lock(srv) is not None, "C3 server up")
        c = mcp_ready(srv)

        # Warm up one full connect/disconnect so any one-time fds (dylibs the
        # first host touches, the reader thread's buffers) are already open;
        # then take the baseline. Measuring after warm-up isolates the
        # PER-RECONNECT growth, which is what a leak would show.
        warm = start_host()
        check(wait_ready(warm), "C3 warm-up host connected")
        close_host(warm)
        _settle_fds(srv.pid)
        baseline = count_fds(srv.pid)
        if not check(baseline is not None, "C3 server fd count is measurable (required)"):
            return

        # The storm: many hosts, each fully connecting (real socket accepted,
        # handshake done, reader thread spawned server-side) and then killed. We
        # COUNT how many actually completed the handshake: if the storm silently
        # failed to connect, the fd/liveness checks below would pass vacuously,
        # so we require the vast majority to have really reconnected.
        storm = 40
        ready_count = 0
        for _ in range(storm):
            nh = start_host()
            if wait_ready(nh, timeout=10):
                ready_count += 1
            close_host(nh)
        check(ready_count >= int(storm * 0.9),
              f"C3 the storm really reconnected ({ready_count}/{storm} completed the handshake)")

        # Let the server observe every disconnect and reap the fds.
        _settle_fds(srv.pid)
        final = count_fds(srv.pid)
        check(final is not None, "C3 server fd count still measurable after the storm")
        # Generous headroom: a handful of fds may legitimately differ (a
        # transient dylib, the last in-flight accept), but a leak of one per
        # reconnect would be ~40. 12 is comfortably below that and above noise.
        if final is not None:
            check(final <= baseline + 12,
                  f"C3 fds stayed bounded (baseline {baseline}, after {ready_count} reconnects {final})")
        check(srv.poll() is None, "C3 server survived the storm")

        # And it still works: a fresh host round-trips a tool call.
        nh = start_host()
        try:
            if check(wait_ready(nh), "C3 a fresh host connects after the storm"):
                check(round_trip_ok(c, nh, title="C3 OK", _id=301),
                      "C3 tool call round-trips after the storm")
        finally:
            close_host(nh)
    finally:
        adv._reap(srv)


def _settle_fds(pid, timeout=10):
    """Poll the fd count until it is stable across two reads or the timeout
    passes. Reader-thread cleanup after a disconnect is asynchronous, so we
    wait on the observable state instead of sleeping a fixed amount."""
    prev = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        cur = count_fds(pid)
        if cur is not None and cur == prev:
            return
        prev = cur
        time.sleep(0.25)


# ---------------------------------------------------------------------------
# C4 - concurrent server starts settle to exactly one reachable bridge
# ---------------------------------------------------------------------------

def c4_concurrent_servers_coexist():
    print("\n[C4] concurrent starts coexist as one broker + relays (LIVE)")
    rounds = 3
    servers_per_round = 6
    for rnd in range(1, rounds + 1):
        adv._rm_lock()
        servers = [adv.start_server() for _ in range(servers_per_round)]
        nh = None
        try:
            # Coexistence (ADR-0024): no instance SIGTERMs another. Under the
            # runtime mutex exactly one binds the socket (the broker); the rest
            # attach as relays. All of them stay alive.
            deadline = time.time() + 20
            lf = None
            while time.time() < deadline:
                alive = [s for s in servers if s.poll() is None]
                lf = e2e.wait_lock(timeout=1)
                if lf is not None and len(alive) == len(servers):
                    break
                time.sleep(0.2)
            alive = [s for s in servers if s.poll() is None]
            check(len(alive) == len(servers),
                  f"C4 round {rnd}: all {servers_per_round} instances coexist ({len(alive)} alive)")
            if not check(lf is not None, f"C4 round {rnd}: exactly one broker owns the lock"):
                continue
            owner = next((s for s in servers if s.pid == lf.get("pid")), None)
            check(owner is not None, f"C4 round {rnd}: the lock names one of the instances")
            if os.name != "nt":
                check(os.path.exists(lf["endpoint"]),
                      f"C4 round {rnd}: broker's socket exists on disk")

            # The load-bearing assertion: the broker's socket round-trips a real
            # attested host + tool call driven from a RELAY (not just the broker),
            # proving the multiplex path is live under concurrent startup.
            relay = next((s for s in servers if owner is not None and s.pid != owner.pid), owner)
            c = mcp_ready(relay)
            nh = start_host()
            if check(wait_ready(nh), f"C4 round {rnd}: a native host handshakes through the broker"):
                check(round_trip_ok(c, nh, title="C4 Coexist", _id=400 + rnd),
                      f"C4 round {rnd}: a relay's tool call round-trips through the broker")
        finally:
            close_host(nh)
            for s in servers:
                adv._reap(s)


def c9_relay_attach_drop_churn():
    print("\n[C9] relay attach/drop churn: broker ref-count stays healthy (LIVE)")
    if os.name == "nt":
        skip("C9 uses the Unix broker/relay coexistence path")
        return
    adv._rm_lock()
    # A stable broker keeps a browser attached the whole time.
    broker = adv.start_server()
    nh = None
    relays = []
    try:
        if not check(e2e.wait_lock(broker) is not None, "C9 broker up"):
            return
        cb = mcp_ready(broker)
        nh = start_host()
        if not check(wait_ready(nh), "C9 browser attached to the broker"):
            return

        # Churn: repeatedly spawn a batch of relays and drop them abruptly. The
        # broker must survive every attach/detach cycle (ref-count never
        # underflows or wedges) and keep serving the browser throughout.
        for cycle in range(4):
            batch = [adv.start_server() for _ in range(3)]
            relays = batch
            time.sleep(0.6)
            alive = [s for s in batch if s.poll() is None]
            check(len(alive) == len(batch), f"C9 cycle {cycle}: relays attached and coexist")
            check(broker.poll() is None, f"C9 cycle {cycle}: broker survives the attach")
            # Drop them hard (SIGKILL) to stress the detach/ref-count path.
            for s in batch:
                sigkill(s)
            for s in batch:
                try:
                    s.wait(timeout=3)
                except Exception:
                    pass
            relays = []
            time.sleep(0.4)
            check(broker.poll() is None, f"C9 cycle {cycle}: broker survives the abrupt relay drop")
            # The broker still owns the lock and still drives the browser.
            lf = e2e.wait_lock(broker, timeout=2)
            check(lf is not None and lf.get("pid") == broker.pid,
                  f"C9 cycle {cycle}: broker still owns the lock after churn")
            check(round_trip_ok(cb, nh, title=f"C9-{cycle}", _id=900 + cycle),
                  f"C9 cycle {cycle}: broker still round-trips a tool call")

        # Finally, detach the last harness (the broker's own): it must exit and
        # remove the lock (ref-count reaches zero).
        broker.stdin.close()
        try:
            broker.wait(timeout=10)
        except Exception:
            pass
        check(broker.poll() is not None, "C9 broker exits once its last harness detaches")
        check(not os.path.exists(e2e.LOCK), "C9 broker removed its lock on final exit")
    finally:
        close_host(nh)
        for s in relays:
            adv._reap(s)
        adv._reap(broker)



# ---------------------------------------------------------------------------
# C5 - server SIGKILLed mid-request -> client sees EOF, a fresh server works
# ---------------------------------------------------------------------------

def c5_server_killed_mid_request():
    print("\n[C5] server SIGKILLed mid-request (LIVE: client EOF, no corruption, recover)")
    if os.name == "nt":
        skip("C5 uses the Unix native-host round-trip")
        return
    adv._rm_lock()
    srv = adv.start_server()
    nh = None
    try:
        check(e2e.wait_lock(srv) is not None, "C5 server up")
        c = mcp_ready(srv)
        nh = start_host()
        if not check(wait_ready(nh), "C5 host connected"):
            return

        # Fire a tool call and read it off the host to confirm it is in flight,
        # then SIGKILL the SERVER (not the host) before any response is sent.
        c.send({"jsonrpc": "2.0", "id": 51, "method": "tools/call",
                "params": {"name": "tab_list", "arguments": {}}})
        req = bounded("C5 in-flight frame read", lambda: e2e.nm_read(nh), 15)
        check(req is not None and req.get("op") == "tab_list",
              "C5 request in flight at the host when the server dies")

        # The MCP client must observe a clean EOF on the server's stdout, not a
        # hang. recv() reads a line; a killed server closes the pipe -> empty
        # read -> json raises. We assert the read TERMINATES (EOF-ish) quickly.
        sigkill(srv)

        def read_resp():
            try:
                return ("json", c.recv())
            except Exception as e:  # empty read / decode error on the closed pipe
                return ("eof", type(e).__name__)

        done, outcome = adv._call_with_timeout(read_resp, 15)
        check(done, "C5 MCP client's read terminated (clean EOF, no hang) after the server died")
        check(done and outcome is not None and outcome[0] == "eof",
              "C5 client saw EOF/broken pipe rather than a corrupt response")

        # Recovery: a brand-new server starts, a host connects, and a tool call
        # round-trips. No stale lock/socket blocks the restart.
        srv2 = adv.start_server()
        nh2 = None
        try:
            if check(e2e.wait_lock(srv2, timeout=8) is not None,
                     "C5 a fresh server starts after the crash"):
                c2 = mcp_ready(srv2)
                nh2 = start_host()
                if check(wait_ready(nh2), "C5 host connects to the fresh server"):
                    check(round_trip_ok(c2, nh2, title="C5 Recovered", _id=52),
                          "C5 tool call round-trips through the recovered server")
        finally:
            close_host(nh2)
            adv._reap(srv2)
    finally:
        adv._reap(nh)
        adv._reap(srv)


# ---------------------------------------------------------------------------
# C6 - peer death in the connect/handshake window -> no stale slot, alive
# ---------------------------------------------------------------------------

def c6_peer_death_in_handshake_window():
    print("\n[C6] peer death in the connect/handshake window (LIVE: no stale slot, alive)")
    if os.name == "nt":
        skip("C6 targets the Unix attestation + handshake window")
        return
    adv._rm_lock()
    srv = adv.start_server()
    nh = None
    try:
        lf = e2e.wait_lock(srv)
        check(lf is not None, "C6 server up")
        c = mcp_ready(srv)

        # (a) DETERMINISTIC anchor: a foreign peer connects straight to the
        # bridge socket and vanishes. The server ACCEPTS it (peer_uid ok) then
        # must reject it at executable attestation and forget it - never
        # creating a slot. Repeating it proves the accept loop survives a run of
        # accepted-then-gone peers. (This is the accept/attestation half of the
        # window; the handshake half is (b). A raw peer cannot pass attestation,
        # so it can never reach the handshake - by design.)
        drops = 10
        for _ in range(drops):
            s = e2e.connect_bridge(lf)
            s.settimeout(3)
            try:
                s.recv(4096)  # server drops without a challenge (clean EOF)
            except Exception:
                pass
            s.close()
        # Poll the server's stderr for the rejection marker (adv.server_stderr
        # returns a non-blocking snapshot while the server is alive). Polling
        # instead of a single read closes the tiny window where the drain
        # thread has not yet appended the line.
        deadline = time.time() + 5
        saw_reject = False
        while time.time() < deadline:
            if "rejected bridge connection" in adv.server_stderr(srv):
                saw_reject = True
                break
            time.sleep(0.1)
        check(saw_reject,
              f"C6(a) server rejected {drops} accepted-then-gone foreign peers at attestation")
        check(srv.poll() is None, "C6(a) accept loop survived the run of vanishing peers")

        # (b) RACY sub-case: real (attested) hosts killed the instant they report
        # a completed socket connect - i.e. inside the attestation+handshake
        # window (the kill may land just before or just after the handshake's
        # last byte; both are valid interleavings the server must survive). We
        # REQUIRE each host to have reached the connected marker, so the server
        # provably accepted and began processing it - otherwise the sub-case
        # would test nothing.
        reached = 0
        for _ in range(8):
            h = start_host()
            if h.connected.wait(8):
                reached += 1
            close_host(h)
        check(reached >= 6,
              f"C6(b) hosts reached the server's connect/handshake window ({reached}/8)")
        check(srv.poll() is None, "C6(b) server survived the in-window host deaths")

        # No stale slot from EITHER sub-case: with nothing connected now,
        # list_browsers must report zero. A leaked slot from a half-authenticated
        # or rejected peer would show a phantom browser here. The server may
        # still be settling the last disconnect, so poll briefly for zero.
        deadline = time.time() + 8
        count = None
        while time.time() < deadline:
            r = bounded("C6 list_browsers", lambda: c.call("list_browsers", {}, _id=601), 15)
            if r is None:
                break
            count = json.loads(r["result"]["content"][0]["text"]).get("count")
            if count == 0:
                break
            time.sleep(0.2)
        check(count == 0, f"C6 no stale browser slot after the window deaths (count={count})")

        # A fresh, well-behaved host connects and round-trips cleanly.
        nh = start_host()
        if check(wait_ready(nh), "C6 a fresh host completes the handshake afterward"):
            check(round_trip_ok(c, nh, title="C6 OK", _id=602),
                  "C6 tool call round-trips after the window deaths")
    finally:
        close_host(nh)
        adv._reap(srv)


# ---------------------------------------------------------------------------
# C7 - stale lock + socket from an ungraceful exit -> next server rebinds
# ---------------------------------------------------------------------------

def c7_stale_lock_and_socket():
    print("\n[C7] stale lock + socket from an ungraceful crash (LIVE: next server rebinds)")
    if os.name == "nt":
        skip("C7 asserts on the Unix filesystem socket left behind")
        return
    adv._rm_lock()
    srv = adv.start_server()
    try:
        lf = e2e.wait_lock(srv)
        if not check(lf is not None, "C7 first server up, lock written"):
            return
        endpoint = lf["endpoint"]
        check(os.path.exists(endpoint), "C7 first server's socket exists on disk")

        # Ungraceful crash: SIGKILL runs NO signal handler, so the lock file and
        # the socket inode are both left behind (a normal exit would have
        # removed them via remove_if_owned).
        sigkill(srv)
        check(os.path.exists(e2e.LOCK), "C7 lock file left stale after SIGKILL")
        check(os.path.exists(endpoint), "C7 socket file left stale after SIGKILL")
    finally:
        adv._reap(srv)

    # The next server must clean up the stale lock+socket and bind fresh, then
    # actually serve: a host connects and a tool call round-trips through it.
    srv2 = adv.start_server()
    nh = None
    try:
        lf2 = e2e.wait_lock(srv2, timeout=8)
        if not check(lf2 is not None and lf2.get("pid") == srv2.pid,
                     "C7 next server rebinds over the stale state (its own lock)"):
            return
        check(os.path.exists(lf2["endpoint"]), "C7 next server's socket exists")
        c = mcp_ready(srv2)
        nh = start_host()
        if check(wait_ready(nh), "C7 a host connects to the rebound server"):
            check(round_trip_ok(c, nh, title="C7 OK", _id=701),
                  "C7 tool call round-trips through the rebound server")
    finally:
        close_host(nh)
        adv._reap(srv2)


# ---------------------------------------------------------------------------
# C8 - browser-gated faults: NOT implemented here (need an isolated Chrome)
# ---------------------------------------------------------------------------

def c8_browser_gated_todo():
    print("\n[C8] browser-gated chaos (SKIP: needs an isolated Chrome, not faked)")
    # These faults live ABOVE the socket/process boundary this suite drives, so
    # a socket-level test cannot exercise them honestly:
    #   - MV3 service-worker eviction mid-op: Chrome evicts the extension SW
    #     while a tool call is outstanding; the extension must re-spawn the host
    #     (connectNative) and the in-flight/next call must recover. Only a real
    #     browser evicts a real SW.
    #   - Reconnect after the server's port closes: the SW observes onDisconnect
    #     and reconnects against the freshly-written lock (the browser half of
    #     the takeover recovery C1/C7 prove at the process level).
    # TODO: implement in tests/browser/ext_test.ts (bun + CHROME_BIN -> isolated Chrome
    # for Testing), gated exactly like the existing browser suite; never against
    # the developer's real Chrome/Brave. Stubbed here so the gap is explicit,
    # not silently missing.
    skip("C8 MV3 service-worker death mid-op / reconnect (TODO: isolated-Chrome ext_test.ts)")


# ---------------------------------------------------------------------------
# C10 - revoke mid-dispatch: the epoch guard drops the harness fail-closed
# ---------------------------------------------------------------------------

def c10_revoke_mid_dispatch():
    print("\n[C10] revoke mid-session (LIVE: epoch guard drops the harness, broker recovers)")
    if e2e.enclave_key_present():
        skip("C10: real enclave key present; pair-client/unkill would raise a live Touch ID prompt (hardware path covered by just touchid-gates)")
        return
    if os.name == "nt":
        skip("C10 uses the Unix harness-attestation path")
        return
    adv._rm_lock()
    adv._rm_clients()
    broker = None
    nh = None
    try:
        # A paired client with a live broker + browser, driving normally.
        adv._pair_client("--name", "pytest", "--this-parent")
        broker = adv.start_server()
        if not check(e2e.wait_lock(broker) is not None, "C10 broker up"):
            return
        cb = mcp_ready(broker)
        nh = start_host()
        if not check(wait_ready(nh), "C10 browser attached"):
            return
        check(round_trip_ok(cb, nh, title="C10-before", _id=1000),
              "C10 the paired client drives the bridge before the revoke")

        # Revoke mid-session from the CLI surface. The next request must be
        # dropped by the per-request epoch guard (fail closed), observed as
        # EOF on the broker's stdout rather than a response.
        subprocess.run([e2e.BIN, "revoke-client", "--name", "pytest"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cb.send({"jsonrpc": "2.0", "id": 1001, "method": "tools/call",
                 "params": {"name": "tab_list", "arguments": {}}})
        line = bounded("C10 revoked call", lambda: broker.stdout.readline(), 10)
        check(line == "", "C10 the revoked harness's next call gets EOF (fail closed)")
        try:
            broker.wait(timeout=8)
        except Exception:
            pass
        check(broker.poll() is not None, "C10 the broker for the revoked harness exits")

        # Re-pair and confirm the bridge fully recovers for a trusted client.
        # A fresh server binding the socket also proves no wedged owner was
        # left holding it after the revoked broker exited.
        adv._pair_client("--name", "pytest", "--this-parent")
        broker2 = adv.start_server()
        try:
            if check(e2e.wait_lock(broker2, timeout=8) is not None,
                     "C10 a re-paired client becomes a fresh broker"):
                cb2 = mcp_ready(broker2)
                nh2 = start_host()
                try:
                    if check(wait_ready(nh2), "C10 browser re-attaches to the new broker"):
                        check(round_trip_ok(cb2, nh2, title="C10-after", _id=1002),
                              "C10 the bridge fully recovers after the revoke")
                finally:
                    close_host(nh2)
        finally:
            adv._reap(broker2)
    finally:
        close_host(nh)
        adv._reap(broker)
        adv._rm_clients()


def c11_revoke_during_sw_death_browser_gated():
    print("\n[C11] revoke during MV3 service-worker death (SKIP: browser-gated)")
    # The extension side of the revoke path -- a host-originated enclave_revoked
    # arriving across an MV3 service-worker restart, and the durable
    # host-revoke-pending flag being re-sent on the next connect -- can only be
    # exercised end to end in an ISOLATED browser (the SW lifecycle, storage.local
    # durability, and the native-messaging port are Chrome-owned). The
    # socket/process half (epoch guard, host key deletion, the push trigger) is
    # covered by C10, the Rust unit tests, and adversarial A17/A18; the
    # extension half by the vitest fakeBrowser suite (enrollment.test.ts,
    # clients.test.ts). The full cross-process interleaving is the isolated
    # security_browser_test's job (CHROME_BIN), never the real browser.
    skip("C11 browser-gated (isolated Chrome); covered piecewise by C10 + unit/adv suites")


def c12_kill_mid_dispatch():
    """ADR-0030 chaos: engage the kill switch while a tool call is IN FLIGHT
    (the browser has the request and will never answer). The severed browser
    leg must fail the caller fast and typed (CONNECTION_LOST via the drained
    pending entry, never a 120s hang), the next call must be the typed
    BRIDGE_KILLED refusal, and an explicit release must fully restore the
    bridge on the same broker."""
    print("\n[C12] kill mid-dispatch (LIVE: in-flight call fails fast; typed refusals; recovery)")
    if e2e.enclave_key_present():
        skip("C12: real enclave key present; pair-client/unkill would raise a live Touch ID prompt (hardware path covered by just touchid-gates)")
        return
    if os.name == "nt":
        skip("C12 uses the Unix harness-attestation path")
        return
    adv._rm_lock()
    adv._rm_clients()
    broker = None
    nh = None
    nh2 = None
    try:
        adv._pair_client("--name", "pytest", "--this-parent")
        broker = adv.start_server()
        if not check(e2e.wait_lock(broker) is not None, "C12 broker up"):
            return
        cb = mcp_ready(broker)
        nh = start_host()
        if not check(wait_ready(nh), "C12 browser attached"):
            return
        check(round_trip_ok(cb, nh, title="C12-before", _id=1100),
              "C12 the bridge works before the kill")

        # Fire a call, wait until the host HOLDS the request (it will never
        # answer), then kill mid-flight.
        cb.send({"jsonrpc": "2.0", "id": 1101, "method": "tools/call",
                 "params": {"name": "tab_list", "arguments": {}}})
        held = bounded("C12 in-flight request reaches the host",
                       lambda: e2e.nm_read(nh), 10)
        check(held is not None and held.get("op") == "tab_list",
              "C12 the request is in flight at the browser")
        subprocess.run([e2e.BIN, "kill"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # The watcher severs the browser leg; the drained pending entry fails
        # the in-flight caller fast (typed), instead of a 120s timeout.
        line = bounded("C12 in-flight call resolves", lambda: cb.recv(), 15)
        text = line["result"]["content"][0]["text"]
        check(line["result"].get("isError") is True and "CONNECTION_LOST" in text,
              "C12 the in-flight call fails fast and typed on the severed leg")

        # Steady state while killed: typed BRIDGE_KILLED refusals.
        r = bounded("C12 next call refused", lambda: cb.call("tab_list", {}, _id=1102), 10)
        text = r["result"]["content"][0]["text"]
        check(r["result"].get("isError") is True and "BRIDGE_KILLED" in text,
              "C12 the next call is the typed BRIDGE_KILLED refusal")

        # Release and recover on the SAME broker.
        e2e.unkill_interactive()
        nh2 = start_host()
        if check(wait_ready(nh2), "C12 a browser re-attaches after the release"):
            check(round_trip_ok(cb, nh2, title="C12-after", _id=1103),
                  "C12 the bridge fully recovers after the release")
    finally:
        close_host(nh)
        close_host(nh2)
        adv._reap(broker)
        e2e.unkill_interactive(check=False)
        adv._rm_clients()


def c13_audit_sink_failure_never_fails_the_decision():
    """ADR-0030 chaos: break the audit file mid-run (replace it with a
    DIRECTORY, so every append fails) while decisions keep being made. Nothing
    may fail because its bookkeeping failed -- tool calls keep flowing, a kill
    still engages and still refuses typed -- and once the sink heals, the
    trail carries a `dropped` counter so the gap is visible."""
    print("\n[C13] audit sink failure during decisions (LIVE: log-after-decide, drop-on-full)")
    if e2e.enclave_key_present():
        skip("C13: real enclave key present; pair-client/unkill would raise a live Touch ID prompt (hardware path covered by just touchid-gates)")
        return
    if os.name == "nt":
        skip("C13 exercises the Unix runtime-dir layout")
        return
    adv._rm_lock()
    adv._rm_clients()
    audit_path = os.path.join(os.path.dirname(e2e.LOCK), "audit.log")
    broker = None
    nh = None
    try:
        adv._pair_client("--name", "pytest", "--this-parent")
        broker = adv.start_server()
        if not check(e2e.wait_lock(broker) is not None, "C13 broker up"):
            return
        cb = mcp_ready(broker)
        nh = start_host()
        if not check(wait_ready(nh), "C13 browser attached"):
            return

        # Break the sink: a directory at the file's path fails every append.
        try:
            os.remove(audit_path)
        except FileNotFoundError:
            pass
        os.mkdir(audit_path)

        check(round_trip_ok(cb, nh, title="C13-broken-sink", _id=1200),
              "C13 tool calls keep flowing while the audit sink is broken")
        r = subprocess.run([e2e.BIN, "kill"], capture_output=True, text=True)
        check(r.returncode == 0, "C13 the kill still engages with the sink broken")
        r2 = cb.call("tab_list", {}, _id=1201)
        text = r2["result"]["content"][0]["text"]
        check(r2["result"].get("isError") is True and "BRIDGE_KILLED" in text,
              "C13 enforcement still refuses typed with the sink broken")
        e2e.unkill_interactive()

        # Heal the sink; the next decisions land, and the writer that failed
        # earlier surfaces its gap as a dropped counter on its next record.
        os.rmdir(audit_path)
        subprocess.run([e2e.BIN, "kill"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        e2e.unkill_interactive()
        cb.call("tab_list", {}, _id=1202)  # a refused-or-served call to audit
        deadline = time.time() + 5
        records = []
        while time.time() < deadline:
            try:
                with open(audit_path) as f:
                    records = [json.loads(ln) for ln in f if ln.strip()]
                if records:
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.2)
        check(bool(records), "C13 the healed sink receives records again")
        kinds = [rec.get("kind") for rec in records]
        check("kill_engage" in kinds and "kill_release" in kinds,
              "C13 post-heal decisions are in the trail")
        dropped = [rec for rec in records if rec.get("dropped")]
        check(bool(dropped),
              "C13 a writer that failed earlier surfaces its gap (dropped counter)")
    finally:
        close_host(nh)
        adv._reap(broker)
        e2e.unkill_interactive(check=False)
        try:
            os.rmdir(audit_path)
        except OSError:
            pass
        adv._rm_clients()


# ---------------------------------------------------------------------------

def main():
    e2e.ensure_binary()          # build with the real environment if missing
    rundir = adv.isolate()       # then lock every subprocess into a private dir
    print(f"binary: {e2e.BIN}")
    print(f"platform: {platform.system()} {platform.machine()}")
    try:
        c1_abrupt_drop_mid_request()
        c2_truncated_nm_frame()
        c3_reconnect_storm()
        c4_concurrent_servers_coexist()
        c5_server_killed_mid_request()
        c6_peer_death_in_handshake_window()
        c7_stale_lock_and_socket()
        c9_relay_attach_drop_churn()
        c10_revoke_mid_dispatch()
        c11_revoke_during_sw_death_browser_gated()
        c12_kill_mid_dispatch()
        c13_audit_sink_failure_never_fails_the_decision()
        c8_browser_gated_todo()
    finally:
        shutil.rmtree(rundir, ignore_errors=True)
    print(f"\n{'=' * 44}\n{_passed} passed, {_failed} failed")
    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
