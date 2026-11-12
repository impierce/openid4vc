---
name: pre-pr-checks
description: Run the checks CI runs on this workspace before opening or updating a pull request, and interpret their failures. Use before every push, when asked "does this pass CI", or when a CI job is red.
---

# Pre-PR checks

CI squash-merges pull requests and runs the checks below. Run them locally first; a push that turns
CI red costs a review cycle. `CONTRIBUTING.md` is the source of truth for the list; this skill adds
the order to run them in and what to do when one fails.

## Commands

Run from the workspace root, in this order (cheapest first):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

When the change touches public items or doc comments, also run:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
```

Feature-gated code (`utoipa`, `test-utils`) must build with and without its feature:

```sh
cargo hack check --workspace --each-feature --locked
```

When the change touches a `Cargo.toml`, `Cargo.lock` or `deny.toml`, also run:

```sh
cargo deny check            # advisories, licenses, bans, sources; policy in deny.toml
cargo +1.95 check --workspace --all-features --locked   # the MSRV from [workspace.package] rust-version
cargo publish --dry-run --workspace --locked             # the five crates still package and build
```

When the change touches a parser or wire type, run its fuzz target for a minute (see the
`fuzz-target` skill): `fuzz/run.sh <target> 60`.

## When a check fails

- **`cargo fmt`**: run `cargo fmt --all` and commit. `rustfmt.toml` sets `max_width = 120`; don't
  fight it with `#[rustfmt::skip]`.
- **`clippy`**: fix the lint. An `#[allow]` needs a comment saying why, on the smallest scope that
  works. Never allow a lint crate-wide to make CI pass.
- **`cargo test`**: a failing specification example test (`*/tests/examples/*.json`) usually means
  the type drifted from the spec, not that the example is wrong. Compare with the cited spec section
  before editing the JSON.
- **`--locked` fails**: the manifests changed without the lockfile. Run `cargo update -p <crate>`
  (or plain `cargo check` to let Cargo add the entries) and commit `Cargo.lock` with the change.
- **`cargo deny`**: a new advisory on a dependency the change did not touch is not this PR's
  problem, but say so in the PR. A new ignore in `deny.toml` needs a `reason` like the existing
  ones, and an ADR in `docs/adr/` if it reflects a design choice. A license outside the allow list
  is a per-crate `exception`, a new git source is not accepted.
- **`cargo publish --dry-run`**: "all dependencies must have a version requirement" means a
  dependency on a workspace crate does not inherit it from `[workspace.dependencies]`, where the
  workspace crates carry their `version` next to the `path`; a file the build needs but the package
  leaves out is missing from `include`. "already exists on crates.io index" is a warning, not a
  failure.
- **MSRV**: the error names the feature or the dependency that needs a newer compiler. Avoid the
  feature; for a dependency, pin the older version in `Cargo.lock` or raise `rust-version` in the
  same PR and say so in the title.
- **`cargo doc`**: bare URLs go in `<...>`; broken intra-doc links need `` [`Type`] `` paths that
  resolve from the crate root (`[`crate::Type`]`, `[`oid4vc_core::Type`]`).
- **Fuzz target panics**: replay the input with `cargo +nightly fuzz run <target>
  fuzz/artifacts/<target>/crash-...`; it is a bug in the parser or an assertion the target states
  too strongly. Fix the bug and add the input as a regular test, or narrow the assertion with a
  comment saying why.

## Before pushing

- The PR title is a Conventional Commit with `!` for breaking changes; it becomes the changelog
  entry. Scope it with the crate name when the change is in one crate: `feat(oid4vp): ...`.
- If the PR implements a row of `docs/FEATURES.md`, flip its status in the same PR.
- If the PR deviates from `docs/DESIGN.md`, add an ADR under `docs/adr/`.
