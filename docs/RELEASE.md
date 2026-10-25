# Release process

Releases are automated with [release-plz](https://release-plz.dev/) and follow
[Cargo's SemVer rules](https://doc.rust-lang.org/cargo/reference/semver.html). Outside the release
pull request, versions are never bumped by hand and the `CHANGELOG.md` files are never edited by
hand (see step 2 of the flow).

Five crates are released: `oid4vc-core`, `oid4vci`, `oid4vp`, `siopv2` and `oid4vc-manager`. Each
has its own version, its own `CHANGELOG.md` next to its `Cargo.toml`, its own tag
(`<crate>-v<version>`, for example `oid4vp-v0.2.0`) and its own GitHub release
([ADR 0001](adr/0001-independent-crate-versions.md)). The root `oid4vc` facade is never released
([ADR 0002](adr/0002-facade-crate.md)).

## Flow

1. On every push to `main`, release-plz checks which crates' files changed since their last
   release. If any did, it opens or updates one release pull request (`chore: release`, labelled
   `release`); otherwise it does nothing. For every changed crate, the pull request contains the
   next version in that crate's `Cargo.toml`, the matching version requirement in the root
   `[workspace.dependencies]` (which the crates depending on it inherit), `Cargo.lock`, and a new
   entry in that crate's `CHANGELOG.md`. Both are derived from the
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

release-plz also runs [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks)
(`semver_check` in [`release-plz.toml`](../release-plz.toml)) against each crate's last version on
crates.io. A breaking API change it finds bumps the minor version even if the pull request title
has no `!`, and the release pull request lists what it found.

## Changelog

Only commits that matter to users of the crates appear in the changelogs: `ci`, `test`, `style` and
`chore` commits are left out, except dependency updates (`chore(deps)`). The rules are configured in
[`release-plz.toml`](../release-plz.toml).

## Adding a crate

crates.io only accepts trusted publishing for a crate that exists. Before a new crate's first
release pull request is merged:

1. Reserve the name with an empty `0.0.0` placeholder, published with a crates.io token scoped to
   publishing new crates. Revoke the token and yank the placeholder afterwards.
2. Configure the trusted publisher on crates.io: repository `impierce/openid4vc`, workflow
   `release-plz.yml`, environment `release`.

## A failed release

The release job publishes the crates in dependency order and stops at the first one that fails, for
example a crate without a trusted publisher (`403 Forbidden: The provided access token is not valid
for crate ...`). Fix the cause and re-run the failed job: it skips the crates already on crates.io
and publishes the rest.

## Credentials

The [release workflow](../.github/workflows/release-plz.yml) runs without long-lived publishing
credentials:

- crates.io accepts the uploads through
  [trusted publishing](https://crates.io/docs/trusted-publishing), only from `release-plz.yml`
  running in the `release` environment, which is limited to `main`.
- The release pull request, tags and GitHub releases are created by the `impierce-release-plz`
  GitHub App, so CI runs on the release pull request like on any other. The App's client ID is the
  Actions variable `RELEASE_PLZ_CLIENT_ID` and a private key of the App is the Actions secret
  `RELEASE_PLZ_PRIVATE_KEY`, set on this repository or on the organization with access to this
  repository. Both come from the App's settings page: the client ID is shown under "About", a
  private key is generated under "Private keys".
