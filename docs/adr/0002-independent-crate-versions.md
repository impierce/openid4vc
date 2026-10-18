# ADR 0002: Crates are versioned, tagged and changelogged independently

- Status: accepted
- Date: 2026-10-18

## Context

The workspace publishes five crates with different rates of change: `oid4vp` moves with every
OID4VP draft, `siopv2` has barely changed since draft 13, `oid4vc-core` changes when a trait does.
All are at `0.1.0` today. `oid4vci`, `oid4vp`, `siopv2` and `oid4vc` were published to crates.io at
`0.1.0` in June 2023; `oid4vc-core` and `oid4vc-manager` never were.

Two models are common for Rust workspaces: lockstep (every crate gets the same version on every
release, as `tokio` or `serde` do not but `bevy` does) and independent (each crate bumps only when
its own files change, as `release-plz` does by default). Pull request #135 already configures the
independent model with per-crate tags.

## Decision

1. Each crate has its own version, its own `CHANGELOG.md` and its own tag,
   `{{ package }}-v{{ version }}` (for example `oid4vp-v0.2.0`).
2. Versions are computed by release-plz from the Conventional Commits that touched the crate, with
   standard Cargo semantics: before 1.0, a breaking change (`feat!:`, `fix!:` or one found by
   `cargo-semver-checks`) bumps the minor version, anything else the patch version. Breaking
   changes are marked with `!` in the pull request title; CI checks the title format.
3. The first release under this process brings every crate to `0.2.0`, including the two that
   were never published, so that the first set of tags reads uniformly and the 2023 `0.1.0` crates
   are visibly superseded. After that, versions drift apart as the crates do.
4. A change in `oid4vc-core` that breaks its dependants is released together with the dependants'
   bumps; release-plz handles the ordering (`oid4vc-core`, then `oid4vci` and `siopv2`, then
   `oid4vp`, then `oid4vc-manager`).

## Consequences

- A consumer can upgrade `oid4vp` without touching `siopv2`, and a changelog lists only what
  changed in the crate it belongs to.
- Scopes in pull request titles matter: `feat(oid4vp): ...` makes the bump land on the right crate.
  A change spanning several crates is one pull request with the broadest accurate scope, or no
  scope.
- `cargo-semver-checks` stays off until the `0.2.0` release gives it a baseline that builds, then
  is turned on (`docs/PLAN.md`, Phase C).
