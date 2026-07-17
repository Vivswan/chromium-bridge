# ADR-0014: Leveled logging (BB_LOG) and typed errors with thiserror

- **Status**: Accepted
- **Date**: 2026-07-10
- **Deciders**: user + AI assistant

## Context

Before the cleanup, the Rust backend's diagnostics were scattered `eprintln!` calls, and error handling was largely "stringly-typed": failures on the tool-call path built a `String` on the spot, with no type distinction, so callers could not branch by error kind, and the `Display` texts were spread everywhere with no way to keep them consistent. Two concrete pain points:

- **No log levels, no switch**: every `eprintln!` either always printed or got deleted; there was no way to raise verbosity temporarily while troubleshooting, and the scattered call sites had no uniform format.
- **Stringly-typed errors**: the errors at the session/tool boundary (not connected, write failure, timeout, disconnect, unknown tool, extension-reported error) were all ad-hoc strings: not enumerable, not matchable, and the `isError` texts were poorly organized.

One hard constraint runs through all of it: **stdout is the protocol stream in both binary modes**. The native host speaks 4-byte-prefixed NM frames and the MCP server speaks NDJSON JSON-RPC (see architecture doc section 3). Any non-protocol byte written to stdout corrupts a frame and drops the connection. So all diagnostics **can only go to stderr**.

## Decision

**Introduce a minimal leveled stderr logger controlled by the `BB_LOG` environment variable (`src/log.rs`), replacing the scattered `eprintln!`; and define typed errors with thiserror on the tool-call path (`src/error.rs`).**

### 1. Leveled logging (`src/log.rs`)
- Four `Level`s: `Error < Warn < Info < Debug`.
- The threshold comes from `BB_LOG` (`error|warn|info|debug`), parsed once at process start through a `OnceLock`; **unset or unrecognized always falls back to `info`**.
- Writes stderr only: `eprintln!("[{LEVEL}] [{tag}] {msg}")`, printed only when past the threshold.
- Provides the `log_error!` / `log_warn!` / `log_info!` / `log_debug!` macros for uniform tag + format.
- Default `info`; `debug` lines are hidden by default, and troubleshooting just needs a launch with `BB_LOG=debug`, no recompile.

### 2. Typed errors (`src/error.rs`)
- The `CallError` enum derives `Error` + `Display` via `thiserror` and covers the error kinds at the tool-call boundary: `NotConnected` / `Write(io::Error)` / `Timeout(Duration)` / `Disconnected` / `UnknownTool(String)` / `Extension(String)`.
- Each variant's `Display` text **is exactly what the model ends up seeing** (surfaced as `isError` via `tools::dispatch`), so the wording is written to be model-readable and actionable.
- The IO/wire layer (`protocol`, `ipc`) keeps using `std::io::Result`; `io::Error` is the right currency at that layer, and `CallError` is not forced onto it. Typing covers only the higher session/tool boundary.

## Alternatives considered

### Logging: the `log` + `env_logger` crates
- **Pros**: the de-facto Rust standard, facade decoupled from backend, complete formatting/filtering features.
- **Cons**:
  - Two crates (plus their transitive dependencies: `env_logger` pulls in `regex`/`termcolor`/time formatting and more), noticeably growing the dependency tree and binary size.
  - This project's need is tiny: four levels, an env threshold, stderr only, fixed format. Most of `env_logger`'s abilities (module-level filtering, colors, timestamps, multiple backends) would go unused.
  - Conflicts with the project's stance of minimal dependencies, auditable artifacts, 608KB (see ADR-0001).
- **Not chosen**: the hand-written logger is about a hundred lines with zero transitive dependencies and fully covers the need.

### Logging: keep bare `eprintln!`
- **Pros**: zero abstraction.
- **Cons**: no levels, no switch, no uniform format; troubleshooting either drowns in output or has nothing to turn up.
- **Not chosen**: the cleanup exists precisely to give diagnostics levels and a switch.

### Errors: stay stringly-typed / adopt `anyhow`
- **Bare String**: not enumerable, not matchable, `Display` scattered.
- **anyhow**: suited to "application top layer, casual `?` + context", but it **erases types**; callers cannot get the concrete variant to branch on, and here the whole point is distinguishable errors at the session/tool boundary (`NotConnected` vs `Timeout` vs `Extension`).
- **thiserror (adopted)**: made for defining **named, matchable, Display-controlled** error enums at a library/boundary, exactly matching "the tool path must distinguish error kinds, and the Display text must be precise and model-facing."

## Consequences

### Positive
- **Controllable diagnostics**: levels + `BB_LOG` let troubleshooting open up verbosity as needed with no recompile; stderr-only guarantees the protocol stdout stays clean.
- **Errors can branch**: the `CallError` variants are matchable, the Displays are model-facing, and the `isError` content is uniformly organized.
- **Dependencies stay restrained**: the logger is hand-written with zero transitive dependencies; errors add only thiserror (a compile-time derive macro with zero runtime cost).

### Negative
- **Two new dependencies**: `libc` (signal-handling related, see below) and `thiserror`. This **revisits ADR-0001's minimal-dependency stance ("the only third-party dependency is serde/serde_json")**, which is now outdated. Accepted after weighing:
  - `thiserror` is a compile-time derive macro, absent at runtime, with minimal size impact, and is the "zero-controversy" choice for defining error types in the Rust ecosystem;
  - `libc` handles low-level stdout/signal interactions (replacing some hand-rolled unsafe/platform details) and is a reasonable dependency for a system-level host.
  - Both are low-risk, widely audited foundational crates, consistent with ADR-0001's "easy to audit" spirit; "exactly two dependencies" merely widens to "a handful of foundational ones."
- **A hand-written logger must be self-maintained**: small as it is, its correctness is ours to guarantee (unit tests cover the level ordering and threshold semantics).

### Neutral
- The log threshold parses once per process through the `OnceLock`; changing `BB_LOG` while running has no effect until restart. Acceptable for long-lived processes like the host/server.

## Implementation

- `src/log.rs`: the `Level` enum, `threshold()` (OnceLock-parsed `BB_LOG`, default `info`), `emit`, the `log_*!` macros; includes level-ordering / threshold unit tests.
- `src/error.rs`: `CallError` (thiserror-derived), Display being the model-visible text; includes Display-text unit tests.
- `Cargo.toml`: `[dependencies]` gains `libc` and `thiserror` (beyond serde/serde_json).
- The tool-call path switches to `CallError`; scattered `eprintln!` migrates to `log_*!`.

## Relationship to other ADRs

- **[ADR-0001](./0001-use-rust-single-binary.md)**: this ADR amends that ADR's statement that "the only third-party dependency is serde/serde_json"; there are now also `libc` and `thiserror`. The minimal-dependency principle stands, only the boundary widens from "two" to "a handful of audited foundational crates"; architecture doc section 8 is updated to match.
- **[ADR-0013](./0013-ci-and-toolchain.md)**: the logger's and error types' correctness is guarded by CI's rust job (clippy + `cargo test`).
