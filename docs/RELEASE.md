# Release process

Releases are automated with [release-plz](https://release-plz.dev/) and follow
[Cargo's SemVer rules](https://doc.rust-lang.org/cargo/reference/semver.html). Versions are never
bumped by hand, and the `CHANGELOG.md` files are never edited by hand.

Five crates are released: `oid4vc-core`, `oid4vci`, `oid4vp`, `siopv2` and `oid4vc-manager`. Each
has its own version, its own `CHANGELOG.md` next to its `Cargo.toml`, its own tag
(`<crate>-v<version>`, for example `oid4vp-v0.2.0`) and its own GitHub release
([ADR 0001](adr/0001-independent-crate-versions.md)). The root `oid4vc` facade is never released
([ADR 0002](adr/0002-facade-crate.md)).

## Flow

1. On every push to `main`, release-plz opens or updates one release pull request
   (`chore: release`, labelled `release`). For every crate whose files changed since its last
   release, it contains the next version in that crate's `Cargo.toml`, the matching version
   requirements in the crates that depend on it, `Cargo.lock`, and a new entry in that crate's
   `CHANGELOG.md`. Both are derived from the
   [Conventional Commits](https://www.conventionalcommits.org/) on `main` that touched the crate.
2. A maintainer reviews the versions and changelogs. To adjust them, commit to the release branch
   shortly before merging, since release-plz regenerates the pull request whenever `main` changes.
3. Approving and merging the release pull request publishes every crate whose version is not on
   [crates.io](https://crates.io/) yet, in dependency order (`oid4vc-core`, then `oid4vci` and
   `siopv2`, then `oid4vp`, then `oid4vc-manager`). Each published crate is tagged and gets a
   GitHub release with its changelog entry.

## Versioning

Before 1.0, a breaking change (`feat!:`, `fix!:` and so on) bumps the minor version
(`0.2.3` → `0.3.0`), and anything else bumps the patch version (`0.2.3` → `0.2.4`). A crate whose
files did not change keeps its version, unless a workspace crate it depends on is released: then
release-plz bumps it too and notes the updated dependency in its changelog.

Pull requests are squash-merged, so the pull request title is the commit that release-plz reads.
The scope decides nothing (the touched files do), but it makes the changelog readable:
`feat(oid4vp): ...`. [`CONTRIBUTING.md`](../CONTRIBUTING.md#pull-requests) describes the title
format.

[`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) is off for now: the 2023
`0.1.0` releases do not build against current dependencies, so there is no baseline to compare to.
It is turned on (`semver_check` in [`release-plz.toml`](../release-plz.toml)) after the first
release.

## Changelog

Only commits that matter to users of the crates appear in the changelogs: `ci`, `test`, `style` and
`chore` commits are left out, except dependency updates (`chore(deps)`). The rules are configured in
[`release-plz.toml`](../release-plz.toml).

## First release

The manifests are at `0.2.0` already, set once by hand before the pipeline existed: `oid4vci`,
`oid4vp` and `siopv2` were published at `0.1.0` in 2023, and the first release brings all five
crates to `0.2.0` (ADR 0001). release-plz sees that `0.2.0` is not on crates.io yet, keeps the
version and only writes the changelogs, which cover everything since the start of the repository.
The 2023 releases were never tagged, so the compare links in those first entries point at tags that
do not exist; fix them in the release pull request if they bother you.

**Publishing is blocked today.** `oid4vc-core` and `oid4vp` depend on the `identity_*` crates as git
dependencies, and the workspace patches `sd-jwt-payload`; `cargo publish` refuses both, and every
other crate depends on `oid4vc-core`. The identity-kit migration
([`PLAN.md`](PLAN.md), Phase D; the migration map in [`DESIGN.md`](DESIGN.md)) removes them. Until
then, release-plz keeps the release pull request up to date, but **do not merge it**: the release
job would fail at the first `cargo publish`.

Once the blockers are gone:

1. `oid4vc-core` and `oid4vc-manager` have never been published, and crates.io only lets you
   configure trusted publishing for a crate that exists. Reserve both names once by hand, for
   example with an empty `0.0.0` placeholder, using a crates.io token scoped to publishing new
   crates; revoke the token afterwards.
2. Configure the trusted publisher on crates.io for all five crates: repository
   `impierce/openid4vc`, workflow `release-plz.yml`, environment `release`.
3. Merge the release pull request. It publishes `0.2.0` of all five crates, tags them and creates
   their GitHub releases; from then on every merged release pull request does the same for the
   crates it bumps.

## Credentials

The [release workflow](../.github/workflows/release-plz.yml) runs without long-lived publishing
credentials:

- crates.io accepts the uploads through
  [trusted publishing](https://crates.io/docs/trusted-publishing), only from `release-plz.yml`
  running in the `release` environment, which is limited to `main`.
- The release pull request, tags and GitHub releases are created by the `impierce-release-plz`
  GitHub App, so CI runs on the release pull request like on any other. The App's credentials are
  stored in the repository variable `RELEASE_PLZ_CLIENT_ID` and the secret
  `RELEASE_PLZ_PRIVATE_KEY` (the same App and credentials as in `impierce/identity-kit`).
