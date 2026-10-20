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
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

When the change touches a `Cargo.toml` or the dependency graph, also run:

```sh
cargo audit                 # advisories, ignores in .cargo/audit.toml
```

When the change touches public items or doc comments, also run:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features
```

Feature-gated code (`utoipa`, `test-utils`) must build with and without its feature:

```sh
cargo check --workspace                       # default features
cargo check --workspace --all-features
```

If `cargo-hack` is installed, `cargo hack check --workspace --each-feature` covers every
combination at once.

## When a check fails

- **`cargo fmt`**: run `cargo fmt --all` and commit. `rustfmt.toml` sets `max_width = 120`; don't
  fight it with `#[rustfmt::skip]`.
- **`clippy`**: fix the lint. An `#[allow]` needs a comment saying why, on the smallest scope that
  works. Never allow a lint crate-wide to make CI pass.
- **`cargo test`**: a failing specification example test (`*/tests/examples/*.json`) usually means
  the type drifted from the spec, not that the example is wrong. Compare with the cited spec section
  before editing the JSON.
- **`cargo audit`**: a new advisory on a dependency the change did not touch is not this PR's
  problem, but say so in the PR. A new ignore in `.cargo/audit.toml` needs a reason comment like the
  existing ones, and an ADR in `docs/adr/` if it reflects a design choice.
- **`cargo doc`**: broken intra-doc links are the usual cause; use `` [`Type`] `` paths that resolve
  from the crate root.

## Before pushing

- The PR title is a Conventional Commit with `!` for breaking changes; it becomes the changelog
  entry. Scope it with the crate name when the change is in one crate: `feat(oid4vp): ...`.
- If the PR implements a row of `docs/FEATURES.md`, flip its status in the same PR.
- If the PR deviates from `docs/DESIGN.md`, add an ADR under `docs/adr/`.
