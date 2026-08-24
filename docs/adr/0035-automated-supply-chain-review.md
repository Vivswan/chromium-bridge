# ADR-0035: Automated supply-chain review replaces the cargo-vet gate

- Status: Accepted
- Date: 2026-08-08

## Context

Since the 2026-07 rebuild, Rust dependencies were gated by `cargo vet`: a CI job failed any PR whose dependency tree contained a crate version without a recorded decision in `supply-chain/`. cargo-vet's promise is strong - a human audited (or deliberately exempted) every crate that enters the build - but this repository mostly did not deliver on it. The initial baseline exempted the entire pre-existing tree, and by retirement `supply-chain/config.toml` was a 1917-line exemptions file against four recorded delta audits (libc, serde_json, thiserror, thiserror-impl) in audits.toml. Real audits happened, but only at the margin: the tree's bulk stayed exemption-backed, and large adoptions (the Tauri tree, ADR-0026) were cleared at policy level rather than read. A gate that is almost always satisfied by `cargo vet add-exemption` asserts little and trains reviewers to rubber-stamp.

The pressure was about to grow. ADR-0034 adopts the official rmcp SDK, pulling in tokio and dozens of new transitive crates - none of which anyone here was realistically going to line-by-line audit, and each of which would have demanded another exemption entry.

Meanwhile the automated stack already existed: `cargo deny` (RUSTSEC advisories, license allow-list, banned sources/wildcards) and `cargo audit` run in `audits.yml` inside every CI gate and again in the weekly `security.yml` sweep, and Dependabot watches cargo, bun, and GitHub Actions. The managed ci.yml also runs GitHub's dependency-review action on every PR (severity gate at `low`).

## Decision

Retire the cargo-vet gate and its data files; rely on fully automated supply-chain checking:

- **Delete** the `cargo-vet` job from `.github/workflows/checks.yml` and the `supply-chain/` directory (audits.toml, config.toml, imports.lock).
- **Keep** cargo-deny + cargo-audit (audits.yml, in the all-green gate and the weekly sweep; locally `moon run audit`) and Dependabot.
- **Rely on the platform-managed dependency-review job** for PR-time advisory checking: the managed ci.yml (delivered and updated by Vivswan/repo-platform sync PRs, per the "Managed by repo-platform" rules in AGENTS.md) runs GitHub's `actions/dependency-review-action` on every PR, failing the gate on dependencies with known advisories (severity `low` and up). Its action version and threshold live in the platform - one place for the whole fleet, not a per-repo twin job.
- **License enforcement stays cargo-deny's job alone**, over the resolved cargo graph with correct SPDX data. Mirroring `deny.toml`'s allow list into the action was built, reviewed, and rejected - see the alternatives below.

## What is actually asserted, before and after

The two stacks make different claims; swapping them trades an unfulfilled strong claim for a kept weak one.

- **cargo-vet asserted** (in theory): a human read this crate's code, or recorded a deliberate decision not to. The reading is an opportunity - not a guarantee - to catch novel malicious code and accidental flaws that no advisory yet records.
- **The automated stack asserts**: no dependency has an *unwaived known-bad record* - RUSTSEC advisories via cargo-deny/cargo-audit on every gate run and weekly, the GitHub Advisory Database via the platform-managed dependency-review job on every PR, Dependabot alerts between runs; the RUSTSEC exceptions reviewed into `deny.toml`'s ignore list (ADR-0026) stay waived - and every license stays inside the reviewed allow-list, enforced by cargo-deny over the resolved Rust graph (the PR-time action carries no license config here; see the rejected alternative below).

Automation that runs beats ceremony that rots: the advisory checks execute identically on every PR and every week, cannot be satisfied by an `add-exemption` reflex, and get better as the databases grow.

## Alternatives considered

- **Keep cargo-vet and actually audit.** Honest, but not real: a single-maintainer project cannot line-by-line review the Tauri tree, let alone rmcp+tokio. Pretending otherwise is worse than not claiming it.
- **Keep cargo-vet in imports-only mode** (trust Mozilla's and other organizations' published audits, exempt the rest). Considered; still carries the exemptions file and its churn on every bump, for a human attestation layer that only covers whatever crates those organizations happen to have audited.
- **Vendor and review only the security core's dependencies.** The core's direct dependency policy already does this socially (ADR-0023: many-eyes crates only, `deny.toml` gates every addition); a formal vendor step adds friction without adding a check.
- **Mirror the license allow-list into a repo-owned dependency-review job.** Built and reviewed, then rejected in favor of the platform's job. The action reads licenses from GitHub's dependency graph, which parses `Cargo.lock` directly and misreports real entries in this tree: the deprecated slash syntax becomes unmatchable `LicenseRef-bad-*` strings (`Apache-2.0/MIT` in dbus and libdbus-sys, `BSD-3-Clause/MIT` in brotli-decompressor), libloading is reported as ISC while being absent from cargo-deny's resolved graph entirely - so no gate checks that crate's license at all today, accepted since ISC is permissive and the crate sits on a Linux-only GUI path - and libfuzzer-sys's NCSA carve-out lives in the fuzz workspace's own `deny.toml`, not the root list. A naive mirror therefore hard-fails legitimate bumps and breeds bogus allow-list entries or purl exemptions; the flat list would also apply to npm and GitHub Actions dependencies `deny.toml` has no opinion on. Duplicating the platform's job would additionally run the action twice per PR and re-create the per-repo pin/threshold sprawl the fleet template exists to remove. If action-level license checks are ever wanted, the allow-list plus purl exclusions belong in the platform's composite action, fleet-wide.

## Consequences

- Dependency bumps no longer require touching `supply-chain/`; Dependabot PRs pass on a green advisory/license check alone.
- `docs/development.md`, `docs/architecture.md`, SECURITY.md, and AGENTS.md now describe the automated stack; the fuzz workspace's vet exemption became moot (its `cargo deny` pass in audits.yml - run from both the CI gate and the weekly sweep - is unchanged). Older ADRs that mention cargo-vet or `supply-chain/` in the present tense (ADR-0026's exemption note, ADR-0028's `supply-chain/config.toml` policy pointer) stay as point-in-time records; this ADR supersedes those mentions.
- The dependency-review action needs a base-to-head diff, so it runs only on `pull_request` events. Direct pushes to main (rare; the branch is protected) and scheduled runs skip it - they remain covered by cargo-deny/cargo-audit in the same gate and by the weekly sweep.
- The PR-time advisory gate is fleet-managed: its action version and severity threshold are Vivswan/repo-platform's to change, arriving via sync PRs - and the managed ci.yml references the action at the floating major tag `@v5`, so patch/minor updates land with no sync PR at all. That is the same managed-refs residual ADR-0033 already accepts for the rest of the managed CI surface.

## Residual risk, named honestly

A **novel malicious crate or an undiscovered vulnerability - anything with no published advisory - now enters the build with no human-audit requirement in its way.** That is the coverage cargo-vet claimed and the automated stack does not have: advisory databases are reactive by definition. A well-executed typosquat or a hijacked minor release of an existing dependency passes the gate until an advisory lands.

Mitigations that remain are real but partial:

- `deny.toml` refuses unknown registries and git sources,
- the license gate forces eyes on anything license-unusual,
- PR review still sees every `Cargo.lock` diff,
- the security core's direct dependencies stay restricted to widely-audited crates by policy (ADR-0023).

Given that the prior gate's coverage was mostly exemptions (four delta audits against a 1917-line exemptions file), this is largely the loss of a claim rather than of practiced enforcement - which is exactly why it is recorded here rather than papered over.
