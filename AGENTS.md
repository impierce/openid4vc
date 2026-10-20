# AGENTS.md

## Project

`openid4vc` is a Cargo workspace of Rust libraries for the OpenID for Verifiable Credentials
specification family: five published crates and one unpublished facade.

| Crate            | Implements                                                                 | Depends on                                  |
| ---------------- | -------------------------------------------------------------------------- | ------------------------------------------- |
| `oid4vc-core`    | shared traits and types: signing, verification, the `Extension` mechanism  |                                             |
| `oid4vci`        | OpenID for Verifiable Credential Issuance 1.0 (wire types, wallet client)  | `oid4vc-core`                               |
| `oid4vp`         | OpenID for Verifiable Presentations 1.0 (DCQL, VP token builder/validator) | `oid4vc-core`, `oid4vci`                    |
| `siopv2`         | Self-Issued OpenID Provider v2 draft 13 (ID token, provider, relying party) | `oid4vc-core`                               |
| `oid4vc-manager` | managers and an `axum` issuer server combining the above; end-to-end tests | all of the above                            |
| `oid4vc` (root)  | facade re-exporting the five crates; not released (ADR 0002)               | all of the above                            |

- `docs/DESIGN.md` is the architecture. Follow it unless there is a concrete reason not to, and
  record any deviation as an ADR in `docs/adr/`.
- `docs/FEATURES.md` is the feature checklist per specification. When a pull request implements a
  row, flip its status to ✅ in that pull request.
- Work is tracked as GitHub Issues labelled `ready-for-agent`. Pick the lowest-numbered open issue
  with no open blockers, one pull request per issue, each with its tests.
- `CONTRIBUTING.md` lists the checks CI runs and the pull request conventions. Read it before
  writing a pull request title.
- `docs/PLAN.md` is the hardening roadmap (CI, fuzzing, release process). Later phases are run as
  `ready-for-agent` issues; the plan says what each one contains.

## Ground rules

- Wire types mirror the specification's JSON exactly. Field names, optionality and defaults come
  from the spec section cited in the type's doc comment. The test oracle is the specification's own
  examples (`*/tests/examples/*.json`, inline vectors), never another implementation's output.
- Extension points are traits (`Subject`, `Sign`, `Verify`, `VerificationMaterialResolver`,
  `CredentialStatusVerifier`, `Storage`) and the `Extension` / `OpenID4VC` type-level mechanism in
  `oid4vc-core`. No closed enum of DID methods, key types or storage backends in the library.
- Protocol logic stays free of I/O where it can. HTTP lives in the `reqwest` clients (`Wallet`,
  `Provider`) and in `oid4vc-manager`'s server; everything else is pure data and functions.
- Cargo features are additive: `utoipa` (OpenAPI schemas) and `test-utils` (mocks and test
  resolvers). Code must build with and without each.
- No new git or path dependencies outside the workspace. The existing `identity_*` git
  dependencies, the `sd-jwt-payload` patch and `did-key` are being replaced by `identity-kit`
  (`docs/PLAN.md`, Phase D); do not deepen their use.
- `deny.toml` is the dependency policy: every advisory ignore carries a `reason`, licenses outside
  the allow list are per-crate `exceptions`, no new git sources. An ignore that reflects a design
  choice also gets an ADR.
- `Cargo.lock` is committed and CI runs `--locked`; a manifest change ships with its lockfile
  change. The MSRV is `rust-version` in `[workspace.package]`; don't use newer features.
- `cargo fmt` (`rustfmt.toml`: `max_width = 120`), `cargo clippy --workspace --all-targets
  --all-features --locked -- -D warnings` and `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
  --workspace --all-features --locked` clean (bare URLs in doc comments go in `<...>`). New
  library code returns errors instead of panicking; don't add `unwrap`/`expect` to parsers or
  validators. A new parser or wire type gets a fuzz target or joins an existing one
  (`fuzz/README.md`).
- Pull request titles are Conventional Commits with `!` for breaking changes, scoped with the
  crate name when the change is in one crate (`feat(oid4vp): ...`). Pull requests are
  squash-merged, so the title is the commit on the default branch and the changelog entry.
  Titles and commit messages use terse commit style, without articles (`CONTRIBUTING.md`).
- Never bump a crate version or edit a changelog by hand; release-plz owns both
  (`docs/RELEASE.md`).

## Agent skills

### Issue tracker

Issues live in GitHub Issues on `impierce/openid4vc` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Repository skills

`.claude/skills/` holds skills specific to this repository; they are committed so they also work in
cloud sessions, where plugins are not installed:

- `pre-pr-checks`: the checks to run before pushing and how to read their failures.
- `spec-example-test`: how to add a test against a specification example.
- `fuzz-target`: how to add or extend a `cargo-fuzz` target and its seeds, and what to do when one
  finds something.
