# Contributing

Thanks for your interest in contributing to `openid4vc`!

## Prerequisites

- A stable Rust toolchain, installed via [rustup](https://rustup.rs/), with the `rustfmt` and
  `clippy` components.
- The minimum supported Rust version (MSRV) is `rust-version` in [`Cargo.toml`](Cargo.toml)
  (`[workspace.package]`) and is checked in CI against the committed `Cargo.lock`. Don't use language
  or standard library features newer than the MSRV without raising it.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) to run the dependency checks locally:
  `cargo install --locked cargo-deny`.
- [`cargo-hack`](https://github.com/taiki-e/cargo-hack) for the feature matrix and
  [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov) for coverage, both optional.

The workspace has git dependencies (see the known gaps in [`docs/DESIGN.md`](docs/DESIGN.md)),
so the first build fetches `iotaledger/identity`; allow a few minutes.

## Layout

| Crate            | What it is                                                                 |
| ---------------- | -------------------------------------------------------------------------- |
| `oid4vc-core`    | shared traits and types used by the protocol crates                        |
| `oid4vci`        | OpenID for Verifiable Credential Issuance 1.0                              |
| `oid4vp`         | OpenID for Verifiable Presentations 1.0                                    |
| `siopv2`         | Self-Issued OpenID Provider v2                                             |
| `oid4vc-manager` | managers, an `axum` issuer server and the end-to-end tests                 |
| `oid4vc` (root)  | facade re-exporting the above; not released                                |

The architecture is described in [`docs/DESIGN.md`](docs/DESIGN.md); the feature checklist in
[`docs/FEATURES.md`](docs/FEATURES.md); decisions in [`docs/adr/`](docs/adr/).

## Checks

CI runs the following checks on every pull request, except `cargo deny`, which runs when a
`Cargo.toml`, `Cargo.lock` or `deny.toml` changes (and the advisory check daily). Run them locally
before opening one:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --all-features --locked
cargo hack check --workspace --each-feature --locked   # feature-gated code builds with and without its feature
cargo deny check                                       # advisories, licenses, bans, sources (deny.toml)
```

`Cargo.lock` is committed and CI runs with `--locked`: a change to a `Cargo.toml` comes with the
matching lockfile update in the same pull request (`cargo update -p <crate>` for a single
dependency). CI also runs the tests on Linux, macOS and Windows, checks that the workspace builds
with the MSRV, and measures test coverage, reported on the pull request via
[Codecov](https://codecov.io/github/impierce/openid4vc) without failing it. To see coverage locally,
run `cargo llvm-cov --workspace --all-features --open`.

### Fuzzing

The parsers are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) from the
[`fuzz/`](fuzz/) crate, a workspace of its own that builds on nightly. Each target feeds arbitrary
input to one surface (credential offers, authorization request URLs, DCQL queries, the OID4VCI and
OID4VP messages) and asserts that nothing panics and that whatever parses survives a round trip. CI
runs every target for a minute on pull requests that touch `*/src/` or `fuzz/`, and for ten minutes
nightly. [`fuzz/README.md`](fuzz/README.md) describes the targets, the seeds and how to run, replay
and extend them.

```sh
cargo install --locked cargo-fuzz
rustup toolchain install nightly
fuzz/run.sh dcql_query 600      # one target, ten minutes
```

### Tests

Unit tests live next to the code, specification examples as JSON under `*/tests/examples/`, and
the end-to-end flows (credential issuance, SIOPv2 and OID4VP) in `oid4vc-manager/tests/`. The test
oracle is the specification: when you add or change a wire type, add the specification's example
for it (see [`.claude/skills/spec-example-test/SKILL.md`](.claude/skills/spec-example-test/SKILL.md)
for the pattern). Never commit another implementation's output as a fixture.

## Pull requests

Pull requests are squash-merged, so the **pull request title** becomes the commit message on the
default branch. It must follow [Conventional Commits](https://www.conventionalcommits.org/):

- `` feat(oid4vp): add `transaction_data` to authorization request ``
- `` fix(oid4vci): make `authorization_details` optional in token response ``
- `` feat(oid4vc-core)!: return typed errors from `Validator::decode` `` (breaking change)

Scope the title with the crate name when the change is in one crate; leave the scope out when it
spans several. Mark a breaking change with `!`: the title will determine the next version number
and the changelog entry once releases are automated, and before 1.0 a `!` bumps the minor version.
So describe the change from a user's point of view.

Write the title, and every commit message, in terse commit style: imperative mood, lowercase after
the colon, no trailing period, no articles (_the_, _a_, _an_), and code literals in backticks, as in
`` feat(oid4vp): add `ClientId` prefixes ``. Write `feat: add description to file`, not
`feat: add a description to the file`.

The pull request body says what changed, why, and how it was tested. If the change implements a
row of [`docs/FEATURES.md`](docs/FEATURES.md), flip its status in the same pull request. If it
deviates from [`docs/DESIGN.md`](docs/DESIGN.md), add an ADR.

## Dependencies

- No new git or path dependencies outside the workspace; the existing ones are being removed
  ([`docs/PLAN.md`](docs/PLAN.md), Phase D).
- Declare shared dependencies in `[workspace.dependencies]` and use `.workspace = true` in the
  crates.
- [`deny.toml`](deny.toml) is the dependency policy. A new advisory ignore carries a `reason`, a new
  license goes in `exceptions` scoped to the crate (not in `allow`) unless it is a policy decision,
  and a new git source is not accepted at all. Most current entries exist because of the `identity_*`
  and `did-key` dependencies; remove them with the dependency.

## Releases

Releases are not automated yet. Versions and changelogs will be generated by
[release-plz](https://release-plz.dev/) from the pull request titles ([`docs/PLAN.md`](docs/PLAN.md),
Phase C; [ADR 0001](docs/adr/0001-independent-crate-versions.md)). Don't bump a version or write a
changelog by hand.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md), and not in
public issues or pull requests.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), as described in section 5 of the license.
