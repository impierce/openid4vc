# Releasing

Versions and changelogs are derived automatically from [Conventional
Commits](https://www.conventionalcommits.org/); publishing to crates.io is always
triggered by hand. The tooling is [release-plz](https://release-plz.dev), configured in
[`release-plz.toml`](release-plz.toml).

Five crates are in the pipeline: `oid4vc-core`, `oid4vci`, `oid4vp`, `siopv2` and
`oid4vc-manager`. The root `oid4vc` facade is excluded (`release = false`) because
nothing depends on it.

## The two workflows

### 1. Prepare Release

Runs on every push to `main`, and can be re-run manually. It opens — and keeps updating —
a single pull request that contains nothing but version bumps and changelog entries for
whichever crates have changed since their last tag. It never publishes anything.

Review that PR like any other. Editing a version by hand in the PR branch is fine if you
disagree with the computed bump. Merging it is what marks a release as ready.

### 2. Release

Manual only (**Actions → Release → Run workflow**). Checkboxes:

| Input | Meaning |
| --- | --- |
| `dry_run` | On by default. Verifies, packages and resolves everything, then stops without uploading or tagging. |
| `oid4vc_core`, `oid4vci`, `oid4vp`, `siopv2`, `oid4vc_manager` | Per-crate. Unchecking one switches it off for that run only. |

For each selected crate whose manifest version is not yet on crates.io, the workflow
publishes it, pushes a `<crate>-v<version>` tag and creates a GitHub release. Crates
already at their published version are skipped, so re-running is safe.

Crates are published in dependency order within a single run, and release-plz waits for
the crates.io index to catch up between them.

## Typical flow

1. Merge feature PRs into `main` using Conventional Commit titles.
2. The release PR appears. Merge it when you want to cut a release.
3. Run **Release** with `dry_run` checked. Read the log.
4. Run **Release** again with `dry_run` unchecked.

## Releasing a single crate

Uncheck the others in step 4. One caveat: if the crate you are releasing depends on
another workspace crate whose new version is not on crates.io yet, `cargo publish` will
fail to resolve it. The dependency order within the workspace is:

```
oid4vc-core  ->  oid4vci  ->  oid4vp  ->  oid4vc-manager
             ->  siopv2   ------------->
```

So release `oid4vc-core` before anything else, and `oid4vc-manager` last.

## How versions are computed

Below 1.0, with the current configuration:

| Commit | Bump |
| --- | --- |
| `feat:` | minor — `0.1.0` → `0.2.0` |
| `fix:`, `refactor:`, `perf:`, `docs:`, `build:` | patch — `0.1.0` → `0.1.1` |
| `ci:`, `chore:`, `test:` | excluded from the changelog |

`feat:` bumping the minor version below 1.0 is deliberate: this repository does not mark
breaking changes with `!` or `BREAKING CHANGE:`, and its features have in practice been
API-breaking. Cargo already treats `0.1` and `0.2` as incompatible, so this is the
honest signal. Once breaking changes are marked explicitly, set
`features_always_increment_minor = false` in `release-plz.toml` to get standard Cargo
semantics back.

Only crates whose own files changed get bumped, which is what allows crates to drift
apart in version.

## Required secrets

| Secret | Used by | Notes |
| --- | --- | --- |
| `CARGO_REGISTRY_TOKEN` | Release | crates.io API token scoped to publish-update, plus publish-new for `oid4vc-core` and `oid4vc-manager`, which have never been published. |
| `RELEASE_PLZ_TOKEN` | Prepare Release | Optional but recommended. A PAT or GitHub App token with `contents: write` and `pull-requests: write`. Without it the default `GITHUB_TOKEN` is used, and CI will not run on the release PR, because `GITHUB_TOKEN` cannot trigger other workflows. |

Consider moving to [crates.io trusted
publishing](https://crates.io/docs/trusted-publishing) once `oid4vc-core` has been
published once; it removes the need for a long-lived `CARGO_REGISTRY_TOKEN`.

## Known blocker

**Nothing can be published to crates.io yet.** `oid4vc-core` depends on
`identity_did`, `identity_document`, `identity_ecdsa_verifier`,
`identity_eddsa_verifier`, `identity_jose` and `identity_verification` as **git**
dependencies pinned to `v1.9.6-beta.1`. Cargo refuses to package a crate with git
dependencies, and that beta is not on crates.io — the newest published `identity_*` is
`1.5.1`. `oid4vp` and `oid4vc-manager` pull in `identity_credential` the same way, and
every other crate depends on `oid4vc-core`, so the whole pipeline is blocked on this.

Resolving it requires one of:

- upstream [iotaledger/identity](https://github.com/iotaledger/identity) publishing
  `1.9.6-beta.1` (or any version this workspace can use) to crates.io;
- moving back to published `identity_*` releases;
- publishing a fork of the `identity_*` crates under a different name.

The same applies to the `[patch.crates-io]` entry for `sd-jwt-payload` in the root
`Cargo.toml`: patches are a workspace-local mechanism and do not carry over to
published crates, so consumers of a published `oid4vp` or `oid4vc-manager` would get
the unpatched `sd-jwt-payload` whose `Hasher` is not `Send + Sync`. Note that
[ssi-agent](https://github.com/impierce/ssi-agent) currently consumes these crates by
git rev, which sidesteps both problems — switching it to crates.io releases means both
have to be resolved first.

Until then, the `dry_run` mode of the Release workflow is the way to check progress — it
fails at exactly the step described above.
