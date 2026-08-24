# ADR-0033: Full adoption of the repo-platform fleet template

- Status: Accepted
- Date: 2026-07-26

## Context

This repository was generated from Vivswan/repo-platform once, then cut loose: the template had no release and its composite actions failed to download, so commit 1bf08ef removed the template wiring, and the platform surfaces were replaced with local equivalents over the following rebuild (a hand-maintained ci.yml with its own all-green needs list, vendored check-typography / check-commit-names / check-all-green scripts, a custom Pages deploy). The managed-file markers stayed in place for a planned re-adoption.

repo-platform has since become a working push-based fleet: a copier template consumed from generated build branches, sync PRs that originate in the platform repository (managed repos carry no sync workflow and no secret), composite actions that other repositories already run in production, central settings apply, and a three-way merge that preserves repository-specific content in shared files. At adoption time (2026-07), two repositories (repo-settings-as-code, skills) are onboarded and green. Maintaining our own copies of what the platform now does buys divergence, not safety.

## Decision

Adopt the template fully, on the `staging` channel, with modules `[agents, bun, rust, pages, release-please, issue-templates, pr-title, auto-assign]`. Concretely:

- **The managed ci.yml owns the gate.** Branch protection still requires only `all-green`; this repository's 18 jobs move verbatim (`cjk` alone additionally gained the local typography-mirror steps) into the repo-owned `.github/workflows/checks.yml`, which the managed ci.yml calls as one aggregated `checks` job. Jobs added to checks.yml are gated automatically, so the vendored needs-list checker (`scripts/check-all-green.ts`) retires.
- **Commit-name enforcement moves to the platform.** The fleet's validate-commit-names action and pr-title job replace the vendored validator, and the `chore` ban is dropped for the fleet-standard type list (release-please's own `chore(main): release` PR was already a carve-out; dependabot now titles its PRs `ci(deps)`/`build(deps)` via the platform's dependabot config). CONTRIBUTING.md still steers toward the most precise type.
- **Releases run through the managed release-please machinery.** The repo-owned release.yml becomes a `workflow_call` pipeline: release-please cuts the release downstream of all-green, and the packaging jobs (binaries matrix, desktop .dmg) run in the same CI run, gated on its `release_created` output. The tag-push trigger and the manual rebuild-for-a-tag dispatch are gone; re-running the original run's jobs covers rebuilds within retention. Publishing requires the `REPO_PLATFORM_TOKEN` repository secret (a PAT): GITHUB_TOKEN-created releases fire no `on: release` workflows, which would silently skip the SBOM and the Pages production deploy. (Since superseded by the draft-first flow: the SBOM now attaches to the draft inside the release pipeline, so only the Pages production deploy still rides `on: release`. Since superseded again by the managed release pipeline: release.yml is now fully template-managed and the packaging jobs live in the repo-owned update-release.yml hook - see [release.md](../release.md).)
- **Pages moves to the platform module.** The managed pages.yml (root = latest release, /staging/ = main HEAD) replaces deploy-site.yml. This gives up the old "staging deploys only the CI-tested sha" guarantee: /staging/ now publishes main HEAD on push, in parallel with CI. Accepted; the production root still only moves on releases.
- **CodeQL runs inside the gate** (managed ci.yml, JavaScript only, as before), replacing the standalone codeql.yml. The platform's reusable workflow runs the AlertSuppression pack, so inline `codeql[...]` suppressions keep working. The analysis category changed, so alerts recorded under the old default category go stale in the Security tab and need one manual dismissal round.
- **repo-platform gained what this repository needed** rather than the repository carrying deltas: a `rust` module (cargo dependabot, Rust gitignore - deliberately outside `has_toolchain`), conventional dependabot commit prefixes, `attestations: write` in the release permissions ceiling, the alert-suppression pack, and doc baselines (SECURITY.md report checklist, issue forms) generalized from this repository's versions.
- Settings stay in this repository's `.github/settings.yml` (the fleet apply reads it when no central file exists).

## Alternatives considered

- **Stay de-adopted.** Keep the vendored copies and the hand-maintained ci.yml. Rejected: the platform now does the same work with sync, and the vendored scripts were already drifting from their upstream (prefix vs exact allowlist semantics, type lists).
- **Adopt the actions but keep our own ci.yml.** Rejected: ci.yml is fully template-managed and sync conflicts resolve in the template's favor, so a bespoke ci.yml would be overwritten on the first sync PR; the sanctioned place for repo jobs is checks.yml, which is what this adoption uses.
- **The `latest` channel.** Preferable for pinning, but the platform has cut no release yet, so `latest` has nothing to consume; staging is also what the owner's other repositories run. Revisit when releases exist.
- **Fork the template.** Maximum control, zero fleet value; rejected for the same reason the vendored copies were.

## Consequences

The template can now push sync PRs here; managed files (`ci.yml`, `release-please.yml`, `dependabot.yml`, `.yamllint`, `.typography-allow`, workflow callers) are edited in repo-platform, not locally. Repo-owned escape hatches: `checks.yml`, `release.yml` (since moved to the managed side, with `release-please.yml` retired; the repo-owned release hook is now `update-release.yml`), `auto-format.yml`, `copilot-setup-steps.yml`, the issue forms, `.gitignore`'s LOCAL section, `.typography-allow.local`, and AGENTS.md's repository-specific section.

## Residual risks, named honestly

- **Mutable refs in the managed workflows.** This repository SHA-pins every action it owns; the managed files do not: `Vivswan/repo-platform/...@main` for the composite actions and reusable workflows, floating major tags for checkout / release-please-action / actionlint / the pr-title action, an unpinned pip-installed yamllint, and an unpinned (first-party) CodeQL query pack. A compromise of repo-platform or of those upstream tags is arbitrary code execution in this repository's CI, with security-events / pages / id-token write in the respective jobs and - via the floating release-please action - contents and pull-requests write plus the REPO_PLATFORM_TOKEN PAT once configured. Accepted on a trust assumption, not a technical boundary: repo-platform stays under the same owner's control, and the alternative is forking the template's value away. The `latest` channel (once the platform cuts releases) pins the platform refs to release tags and is the planned tightening. Locally, the moon gate pins yamllint; local actionlint comes from brew and floats too - CI divergence there surfaces findings, never hides them.
- **The weekly CodeQL cron re-runs the whole gate**, including the heavy checks.yml jobs (macOS/Windows runners). Fleet convention; runner cost accepted.
- **auto-format pushes with GITHUB_TOKEN**, whose commits trigger no CI: after a `fix-lint` run, the PR head has no all-green result until someone re-runs CI. Fail-safe (the merge stays blocked), so accepted as shipped.
- **The local typography mirror is deliberately stricter** than the platform action (exact-path exemptions vs prefixes): anything the local gate passes also passes CI, never the reverse.
