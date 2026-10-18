# ADR 0001: The default branch is `main`

- Status: accepted
- Date: 2026-10-18

## Context

The repository's default branch is `dev`. A `main` branch exists but holds only the initial commit
from March 2023 and is 50 commits behind `dev`. The workflows disagree about which branch matters:
`format-lint-test.yaml` runs only on `dev`, `audit.yaml` runs on pull requests to `main`, `next`,
`beta` and `alpha` (so never on a pull request to `dev`). The sibling repository `identity-kit`,
and the release tooling planned for this one (release-plz, pull request #135), assume `main`.

`impierce/ssi-agent` consumes these crates by git reference. A branch rename keeps commit pins
(`rev = ...`) valid and breaks `branch = "dev"` references.

## Decision

1. `main` becomes the default branch, by renaming `dev` to `main` in GitHub (which redirects open
   pull requests and local clones), after the current content of `main` is discarded. The stale
   `main` is replaced, not merged: it contains nothing `dev` does not.
2. The rename happens as its own step after the workflows reference `main` (Phase B of
   `docs/PLAN.md`), and after checking that `ssi-agent` pins a commit rather than the `dev` branch.
3. Until then, documentation says "the default branch" rather than naming it.

## Consequences

- One branch name across `identity-kit`, `openid4vc` and the release tooling.
- The audit workflow finally runs on pull requests.
- Anyone with `branch = "dev"` in a manifest has to update it once; GitHub's redirect covers
  clones and open pull requests.
