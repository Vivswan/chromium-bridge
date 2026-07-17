# ADR-0001: Rust single binary with subcommand dispatch

- **Status**: Accepted (the dependency-list part is amended by [ADR-0014](./0014-leveled-logging.md))
- **Date**: 2026-07-07
- **Deciders**: user + AI assistant

> **Amendment note**: this ADR originally said the only dependencies are
> `serde`/`serde_json`. The engineering cleanup later added `libc` (signal
> handling) and `thiserror` (typed errors); see [ADR-0014](./0014-leveled-logging.md).
> The core decisions (single binary, hand-written protocol, no tokio) are unchanged.

## Context

The browser-bridge backend has to play two roles at once:

1. **MCP server**: spawned by the MCP client through its MCP server config, speaking JSON-RPC over stdio
2. **Native Messaging host**: spawned by Chrome through the host manifest, speaking 4-byte length-prefixed frames over stdio

Both roles are long-running, both handle a binary protocol on stdin/stdout, and both need to be reliable.

The first design draft (based on an incorrect environment probe that found "only Python 3.9.6", later corrected) used the Python standard library. When the environment was verified, the user's machine turned out to have Homebrew Rust 1.96, and Rust has clear advantages for this scenario.

## Decision

**Write the backend in Rust, compiled into a single binary, with subcommand dispatch:**

- Default invocation (no arguments) = MCP server mode
- `--native-host` = native host mode
- `--help` = help

The two modes share the same crate and the same protocol code (`protocol.rs`); only the entry dispatch differs.

## Alternatives considered

### Option A: Python standard library (the original design)
- **Pros**: zero compilation; cross-platform; the standard library is sufficient
- **Cons**:
  - Runtime dependency on a Python environment (the user's machine has one, but it is Homebrew-installed and not necessarily on PATH)
  - The host manifest `path` has to point at a Python interpreter plus a script, making the wrapper more complex
  - Performance/memory worse than a compiled language (long-running process)
  - **The decisive problem**: the user's actual Python environment is a Homebrew multi-version install, the system `python3` is 3.9.6, and which one the host would start with is uncertain and fragile

### Option B: Two separate Rust crates (one for the host, one for the mcp-server)
- **Pros**: clear responsibility boundary; minimal dependencies for each
- **Cons**:
  - Two compiled artifacts to distribute in sync
  - Shared protocol code would have to be split into a workspace sub-crate, adding structural complexity
  - An upgrade has to replace two files

### Option C: Go
- **Pros**: single binary; easy cross-compilation; GC, which does not matter for this scenario
- **Cons**: the user's machine has no Go installed (verified: `which go` not found); a toolchain would have to be installed first
- **Rejected**: Rust is already in the user's environment (Homebrew); Go would have to be installed

### Option D: Rust + tokio (async)
- **Pros**: mature concurrency model; rich ecosystem
- **Cons**:
  - Requests are serial (one round trip per tool call), so there is no high-concurrency requirement
  - tokio adds binary size (several MB), compile time (tens of seconds), and complexity for nothing
  - std threads plus mpsc channels are entirely sufficient

## Consequences

### Positive
- **Single-binary distribution**: upgrading = copying one file; the host manifest `path` is an absolute path, independent of PATH (which matches the real constraint that the user's PATH does not contain homebrew)
- **Small artifact**: release + opt-level z + lto, 608KB
- **Zero runtime dependencies**: the user's machine needs no runtime at all (compare the Python option)
- **Shared code**: both modes share the NM frame, MCP JSON-RPC, and bridge protocol definitions in `protocol.rs`
- **Panic safety**: Rust's `panic = "abort"` plus a stderr hook makes it easier to guarantee stdout stays clean than Python exceptions do

### Negative
- **Compilation needs a Rust toolchain**: the user's machine has one (Homebrew 1.96), but first-time dev-environment setup is slightly heavier than Python
- **`install.sh` has to handle PATH**: the `cargo` subprocess depends on `rustc` being on PATH, and the user's PATH does not contain `/opt/homebrew/bin`. Handled in install.sh with `export PATH="$(dirname $CARGO):$PATH"`
- **Code changes require recompilation**: development iteration is slower than Python (release ~45s, dev ~5s)

### Neutral
- `serde`/`serde_json` is the only third-party dependency, close to a "zero-controversy" choice in the Rust ecosystem; the audit surface is 1 crate

## Implementation

- `Cargo.toml` single crate; profile.release sets `opt-level="z"` + `lto=true` + `panic="abort"`
- `src/main.rs` dispatches on `args[1]` to `mcp_server::run()` or `native_host::run()`
- `install.sh` compiles and copies to `~/.browser-bridge/browser-bridge`, using a `run-host.sh` wrapper to add the `--native-host` argument (working around the NM manifest having no args field)

## References

- User environment verification: `/opt/homebrew/bin/cargo` 1.96.1 (Homebrew); `~/.cargo` has no cargo/rustc (not rustup)
- Existing hosts of the same kind (Claude/Codex/AutoClaw) are all compiled binaries, which corroborates this choice
