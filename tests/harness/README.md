# Harness interop smoke suite

Proves REAL agent-harness CLIs (Claude Code, Codex) can connect to the bridge's stdio MCP server, and captures the exact JSON-RPC frames each harness sends. The live fake-LLM entries go further: a full model-driven MCP tool call through each CLI, with the model played by a local fake backend - zero credentials, zero model spend, deterministic.

## Run

```sh
moon run harness-smoke                 # or: bun tests/harness/run.ts
bun tests/harness/run.ts --mint-seeds  # also mint captured frames as fuzz seeds
```

- Harnesses whose CLI is not on PATH are skipped with a message. `BB_HARNESS_<NAME>_BIN` (e.g. `BB_HARNESS_CLAUDE_BIN`) pins a specific executable; by default the driver skips terminal-mux proxy shims (cmux) on PATH, which break stdio MCP health checks.
- Captures land in `build/harness-captures/<harness>.ndjson` (gitignored) plus a `summary.json`; CI's nightly `harness-smoke.yml` uploads the directory as an artifact.
- `--mint-seeds` copies deduplicated captured frames into `src/packages/core/fuzz/seeds/mcp_jsonrpc/` with descriptive names (`harness-claude-initialize`, ...) - a real-world corpus for the fuzzer. Review and commit the new seeds deliberately.

## The ADR-0034 canary

The suite prints one `CANARY` line per harness naming the OPENING method it sent:

- `initialize` - the legacy MCP handshake; the temporary legacy shim (ADR-0034) is still required.
- `server/discover` - the modern 2026-07-28 opening; once EVERY harness reports this, the legacy shim can be deleted.

## Isolation (safety)

- Each harness runs against an ISOLATED config dir in a throwaway scratch dir (`CLAUDE_CONFIG_DIR` / `CODEX_HOME`); the user's real harness config is never read or written.
- The registered server command is a generated tee shim that logs stdin frames to the capture file and pipes them into the real `target/release/chromium-bridge`. The shim also points the server's `XDG_RUNTIME_DIR` / `XDG_CONFIG_HOME` / `HOME` into the scratch dir, so the spawned server can never attach to (or become) the user's real bridge broker, and never reads real pairing or kill-switch state.
- No browser is involved: the server runs with no native host attached.

## Probes without model calls

- Claude Code: `claude mcp list` health-checks every approved server with a real MCP handshake - a genuine connection probe, no model call. (It runs unauthenticated today; a claude release that starts requiring login for it would read as a red night rather than a server regression.)
- Codex: `codex mcp list --json` only verifies registration (reported as "configured"). The real-backend live probe runs a REAL codex agent session (read-only sandbox), so it requires `OPENAI_API_KEY` plus the explicit `BB_HARNESS_CODEX_LIVE=1` opt-in - an ambient key alone never launches an agent. (The fake-LLM probe below needs neither.)
- After registering, the driver asserts the entry landed in the ISOLATED config file and refuses to probe otherwise (a harness that ignored the isolation env var may have written the real user config - fail closed).
- `--require-any` (used by the nightly workflow) fails the run unless at least one harness completed a live MCP connection, so an install failure or a config-entry-only run cannot read as green.

## Live tool-call probes (fake LLM backend)

The `claude-live-fakellm` and `codex-live-fakellm` entries run whenever the CLI is installed - no API key, no opt-in, because no credential and no real model is involved. `tests/harness/fake-llm.ts` plays the model on an ephemeral 127.0.0.1 port (Anthropic Messages API for `claude -p` via `ANTHROPIC_BASE_URL` + a dummy key; OpenAI Responses API for `codex exec` via `model_providers` base_url overrides - codex 0.146+ refuses `wire_api = "chat"`), so a REAL harness run performs a full prompt -> tool call -> tool result -> final text loop deterministically.

The canned scenario is content-addressed, not turn-counted: a request carrying a tool result gets final text; a request advertising the bridge's `tab_list` gets a call to it (under whatever name the harness advertised: `mcp__chromium-bridge__tab_list` for claude, the `mcp__chromium_bridge` namespace for codex); anything else (title generation, token counting) gets a trivial reply. `GET /_test/requests` serves everything the backend saw for the driver's assertions.

Each probe asserts three points and fails closed on any of them:

1. the fake backend saw the bridge's `tab_list` advertised among the request's tools and told the harness to call it;
2. the tee shim captured the resulting `tools/call` frame, in the same protocol era as the harness's opening method;
3. the tool result fed back to the model echoed the scenario's invocation id and carried the bridge's typed `Error [NOT_CONNECTED]` text - no browser is attached, so that IS the expected outcome (the 12s connect-wait makes this the slow step).

The fake backend binds 127.0.0.1 only. Two artifacts land next to the captures for red-night forensics: `<entry>.fake-llm.log` (the backend's stderr/stdout) and `<entry>.fake-llm-requests.json` (every request body the backend saw, so a harness release that changes shape explains itself). A side effect worth knowing: `--mint-seeds` now mints real `tools/call` frames into the fuzz corpus, which the health-check probes never produced.

## Adding a harness

Add an entry to `HARNESSES` in `run.ts`: a CLI name (the availability probe), `isolationEnv` (config-isolation env vars - never the user's real config), `configFile` (where the registration must land, for the fail-closed isolation assertion), `configure` (register the shim as a stdio MCP server), and `probe` (prefer the CLI's offline health check; gate anything needing a model call behind its API key env var plus an explicit opt-in).
