# Governance

How changes get made in chromium-bridge. Small project, light process - but the process that exists is enforced by CI, not by memory. See also [CONTRIBUTING.md](CONTRIBUTING.md) (dev workflow) and [SECURITY.md](.github/SECURITY.md) (security bar).

## Branching

Trunk-based. `main` is always releasable.

```
main
 ├── feat/...
 ├── fix/...
 ├── refactor/...
 └── docs/...
```

Branch prefixes use the Conventional Commits types
(`build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test`; see
[CONTRIBUTING.md](CONTRIBUTING.md)). No long-lived `develop`. Branches merge via PR and are deleted after merge.

`main` rules (enforced where possible via branch protection):

- changes land through PRs with green CI;
- no force-push;
- security-relevant PRs get extra scrutiny (see below);
- even the solo maintainer uses PRs for non-trivial work, to keep CI in the loop.

## Definition of Done

A change is done when:

- inputs are typed and (for tools) schema-validated;
- a new/changed tool has a risk level in the [risk matrix](docs/security/tool-risk-matrix.md);
- the permission/allowlist/confirmation path is clear;
- there are **positive and negative** tests (negative especially for security);
- errors have stable codes; logs contain no sensitive data;
- docs / generated files / CHANGELOG are updated;
- CI is green;
- no unexplained `any`, `unwrap()`/`expect()` on a production path, or new permission slipped in.

## Security-relevant changes

If a change touches permissions, credential access, confirmation, allowlist, masking, bridge auth, the lock file/secret, or widens `page_eval` (full list in [SECURITY.md](.github/SECURITY.md)):

- use the [security-change issue/PR checklist](.github/ISSUE_TEMPLATE/security-change.yml);
- update the [tool risk matrix](docs/security/tool-risk-matrix.md) and, if a trust boundary moves, the [threat model](docs/security/threat-model.md);
- add a negative test proving the boundary still holds.

## Decisions: ADR vs RFC

- **ADR** (`docs/adr/`) records a decision *already made*: why single-binary, why a given confirmation UI. Status: Proposed / Accepted / Superseded / Deprecated.
- **RFC** (open a discussion/issue) proposes a *significant change* before building it: a write capability, a new protocol version, a new browser platform, enterprise policy.

The RFC flow, in order:

1. open the RFC as a discussion or issue;
2. discuss; the RFC is accepted or rejected;
3. implement;
4. an ADR records the outcome.

## Tracking work & tech debt

Tech debt lives in GitHub Issues, not in comments or memory. Type labels:

```
type:feature  type:bug  type:security
```

A tech-debt issue states: the problem, the risk, the current workaround, the target state, and what should trigger addressing it.

## Repository root is reference-locked

The files at the repository root are intentionally minimal, and most of them **cannot move** without breaking tooling: a "tidy-up" that relocates them will silently break the build or lint gates. Before moving anything at root, know why it is there:

| File | Why it stays at root |
|---|---|
| `Cargo.toml`, `Cargo.lock` | Tool-pinned: the cargo crate root |
| `rust-toolchain.toml` | Tool-pinned: rustup resolves it from the project root |
| `rustfmt.toml`, `clippy.toml` | Tool-pinned: `cargo fmt` / clippy discover them from the crate root; no CLI override is set |
| `deny.toml` | Tool-pinned: `cargo deny check` is invoked bare, so it uses the default root path |
| `.editorconfig`, `.gitignore`, `.gitattributes` | Tool-pinned: walked up from the working tree |
| `README.md`, `LICENSE.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `CHANGELOG.md`, `AGENTS.md` | Convention: GitHub surfaces them at root |
| `moon.yml` (with `.moon/` and the per-project `moon.yml` files) | Referenced by path as the canonical task entrypoint; moving it means editing every reference |

If a genuine reason to relocate one appears, update every reference in the same change (CI workflows, moon tasks, `scripts/`, docs, `.github/CODEOWNERS`) and confirm the lint/build gates still find their config.

## Versioning & release

- `Cargo.toml` is the single source of truth; `moon run sync-version` propagates it.
- Releases are cut by release-please from a green `main`: merging the rolling release PR tags `vX.Y.Z`, and the same CI run builds and publishes the assets ([docs/development.md](docs/development.md#releasing)).
- SemVer discipline applies even pre-1.0: a `0.x` bump is not a license to break compatibility silently. Tool removal/rename, permission widening, and protocol breaks are "major"-shaped.
