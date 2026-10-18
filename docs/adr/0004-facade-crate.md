# ADR 0004: The root `oid4vc` crate is a facade and is not released

- Status: accepted
- Date: 2026-10-18

## Context

The workspace root `Cargo.toml` is also a package: `oid4vc`, which re-exports the five crates
(`pub use oid4vc_core; pub use oid4vci; ...`) through path dependencies without version
requirements. It was published to crates.io at `0.1.0` in June 2023 and has not been touched
since. Nothing in `impierce/ssi-agent` depends on it; consumers pick the crates they need.

Options:

- Publish it as an umbrella crate on every release (one more crate to version, with a version that
  means nothing on its own and that must bump whenever any member bumps).
- Keep it as a local convenience and never release it (`release = false` in `release-plz.toml`, as
  pull request #135 proposes).
- Delete it and leave the 2023 `0.1.0` on crates.io as a dead end.

## Decision

1. `oid4vc` stays in the workspace as the facade and development root (`cargo test --workspace`
   runs from here), and is excluded from releases with `release = false`.
2. Its manifest gets `publish = false` so that `cargo publish` cannot be run on it by accident, and
   its description says what it is.
3. The crates.io page of `oid4vc 0.1.0` is left as is; when the five crates publish their `0.2.0`
   releases, the facade's README on crates.io cannot be updated without a release, so the
   workspace `README.md` (which GitHub shows) is the place that points consumers at the individual
   crates.

## Consequences

- One fewer version to reason about; the changelogs stay per crate (ADR 0002).
- The facade can keep path-only dependencies, which would otherwise fail `cargo publish`.
- Should an umbrella crate become useful (for example for `docs.rs` navigation), flipping
  `release = false` and adding version requirements to its dependencies is a small, separate
  decision.
