# Harness interop smoke suite

Proves REAL agent-harness CLIs (Claude Code, Codex) can connect to the
bridge's stdio MCP server, and captures the exact JSON-RPC frames each
harness sends.

## Run

```sh
moon run harness-smoke                 # or: bun tests/harness/run.ts
bun tests/harness/run.ts --mint-seeds  # also mint captured frames as fuzz seeds
```

- Harnesses whose CLI is not on PATH are skipped with a message.
  `BB_HARNESS_<NAME>_BIN` (e.g. `BB_HARNESS_CLAUDE_BIN`) pins a specific
  executable; by default the driver skips terminal-mux proxy shims (cmux)
  on PATH, which break stdio MCP health checks.
- Captures land in `build/harness-captures/<harness>.ndjson` (gitignored)
  plus a `summary.json`; CI's nightly `harness-smoke.yml` uploads the
  directory as an artifact.
- `--mint-seeds` copies deduplicated captured frames into
  `src/packages/core/fuzz/seeds/mcp_jsonrpc/` with descriptive names
  (`harness-claude-initialize`, ...) - a real-world corpus for the fuzzer.
  Review and commit the new seeds deliberately.

## The ADR-0034 canary

The suite prints one `CANARY` line per harness naming the OPENING method it
sent:

- `initialize` - the legacy MCP handshake; the temporary legacy shim
  (ADR-0034) is still required.
- `server/discover` - the modern 2026-07-28 opening; once EVERY harness
  reports this, the legacy shim can be deleted.

## Isolation (safety)

- Each harness runs against an ISOLATED config dir in a throwaway scratch
  dir (`CLAUDE_CONFIG_DIR` / `CODEX_HOME`); the user's real harness config
  is never read or written.
- The registered server command is a generated tee shim that logs stdin
  frames to the capture file and pipes them into the real
  `target/release/chromium-bridge`. The shim also points the server's
  `XDG_RUNTIME_DIR` / `XDG_CONFIG_HOME` / `HOME` into the scratch dir, so
  the spawned server can never attach to (or become) the user's real bridge
  broker, and never reads real pairing or kill-switch state.
- No browser is involved: the server runs with no native host attached.

## Probes without model calls

- Claude Code: `claude mcp list` health-checks every approved server with a
  real MCP handshake - a genuine connection probe, no model call.
- Codex: `codex mcp list --json` only verifies registration (reported as
  "configured"). The live probe runs a REAL codex agent session
  (read-only sandbox), so it requires `OPENAI_API_KEY` plus the explicit
  `BB_HARNESS_CODEX_LIVE=1` opt-in - an ambient key alone never launches
  an agent.
- After registering, the driver asserts the entry landed in the ISOLATED
  config file and refuses to probe otherwise (a harness that ignored the
  isolation env var may have written the real user config - fail closed).
- `--require-any` (used by the nightly workflow) fails the run unless at
  least one harness completed a live MCP connection, so an install failure
  or a config-entry-only run cannot read as green.

## Adding a harness

Add an entry to `HARNESSES` in `run.ts`: a CLI name (the availability
probe), `isolationEnv` (config-isolation env vars - never the user's real
config), `configFile` (where the registration must land, for the
fail-closed isolation assertion), `configure` (register the shim as a
stdio MCP server), and `probe` (prefer the CLI's offline health check;
gate anything needing a model call behind its API key env var plus an
explicit opt-in).
