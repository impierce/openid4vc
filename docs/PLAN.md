# openid4vc: hardening and release plan

- Date: 2026-10-18
- Status: Phase A implemented (this document's PR); Phases B–D open
- Basis: side-by-side comparison of `impierce/openid4vc` (`dev` @ 64036ca) with `impierce/identity-kit`
  (`main` @ dfceb57), plus the GitHub state of both repos (issues, PRs, releases, crates.io).

The goal is parity with identity-kit's engineering setup, adapted to a five-crate workspace, in an
order that lets agents do the later steps. Phase A (agentic setup) comes first so every later phase
can be run as `ready-for-agent` issues.

---

## 1. Findings

### 1.1 What identity-kit has and openid4vc lacks

| Area | identity-kit | openid4vc | Gap |
| --- | --- | --- | --- |
| Agent instructions | `AGENTS.md` (project, ground rules, agent skills) | none | **missing** |
| Skill config | `docs/agents/{issue-tracker,triage-labels,domain}.md`, `.claude/settings.json` enabling `mattpocock-skills` | none | **missing** |
| Architecture doc | `docs/DESIGN.md` (principles, layout, module contracts, conformance) | none; crate READMEs are marketing text | **missing** |
| Feature checklist | `docs/FEATURES.md` with status, Cargo feature, spec link, issue | none (PR #93 from 2025 proposes an OID4VP checklist, never merged) | **missing** |
| Decision log | `docs/adr/0001..0005` | none | **missing** |
| Contributing / security | `CONTRIBUTING.md`, `SECURITY.md`, `CODEOWNERS` | none; issue templates and a generic PR template only | **missing** |
| Dependabot | cargo + actions, weekly, grouped, 7-day cooldown | none | **missing** |
| Lockfile | `Cargo.lock` committed, `--locked` everywhere | `**/Cargo.lock` gitignored | **missing**: CI is not reproducible, `--locked` impossible |
| CI: QA | fmt, clippy `-D warnings`, test on 3 OSes, rustdoc `-D warnings`, MSRV from `rust-version`, one aggregate `qa` job for branch protection | one job (fmt, clippy, test) that runs **only on `dev`** | weak |
| CI: coverage | `cargo-llvm-cov` + Codecov via OIDC, `codecov.yml` informational | `cargo-llvm-cov` + Codecov with `CODECOV_TOKEN`, runs on every push and PR | ok, hygiene only |
| CI: advisories | `cargo-deny check advisories`, daily + on manifest changes, `deny.toml` with reasoned ignores | `cargo audit`, daily + on PRs to `main`/`next`/`beta`/`alpha` (so **never on PRs to `dev`**), `.cargo/audit.toml` ignores | misconfigured |
| CI: licenses/bans/sources | `cargo-deny check licenses bans sources` | none | **missing** |
| CI: fuzzing | 8 `cargo-fuzz` targets, seeds from spec vectors, 1 min per PR, 10 min nightly, corpus cached | none | **missing** |
| CI: PR title | `action-semantic-pull-request` | none (but all 50 commits on `dev` are already conventional, one typo `feat :`) | **missing** |
| CI hygiene | actions pinned to SHAs, `permissions: contents: read`, `persist-credentials: false`, concurrency groups | unpinned `@v7`/`@stable`, no `permissions`, no concurrency | weak |
| Release | release-plz, release PR, trusted publishing, GitHub App token, `docs/RELEASE.md` | draft PR #135 (see 1.3), no tags, no releases, no changelog | **missing** |
| Versioning | `rust-version = "1.85"`, `edition = "2024"`, `include = [...]`, docs.rs metadata | all crates `0.1.0`, no `rust-version`, `edition = "2021"`, no `include`, no docs.rs metadata | weak |
| Lints | `forbid(unsafe_code)`, `missing_docs`, `unreachable_pub`, clippy `dbg_macro`/`todo`/`print_*` | none; 395 `unwrap`/`expect` in `*/src` | weak |
| Triage vocabulary | `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix` | `Bug`, `Request`, `Dependencies`, `Breaking change`, `Enhancement`, `Chore`, `Added`, `Documentation`, `Help wanted` | no agent states |

### 1.2 Repository state

- **Default branch is `dev`.** `main` is one commit, "Initial commit" from 2023-03-21, 50 commits behind.
  PR #135 proposes switching the default to `main`; `format-lint-test.yaml` and `audit.yaml` disagree
  about which branch matters today.
- **Merging:** squash merges (zero merge commits on `dev`), PR titles conventional. Breaking changes
  are not marked with `!`, which matters once release-plz derives versions from titles.
- **crates.io:** `oid4vci`, `oid4vp`, `siopv2` and the umbrella `oid4vc` exist at `0.1.0` (2023-06-12).
  `oid4vc-core` and `oid4vc-manager` have never been published. The published 0.1.0 crates no longer
  build against current dependencies (PR #135 notes this), so `cargo-semver-checks` has no baseline.
- **Publishing blockers (all must go before any crate can be published):**
  1. Eight `identity_*` crates as **git dependencies** on `iotaledger/identity` tag `v1.9.6-beta.1`,
     used in `oid4vc-core` (verifier, verification material resolver), `oid4vp` (DCQL, VP token
     builder/validator: 47 references), `oid4vci` (2), `oid4vc-manager` tests (1). Cargo refuses to
     package crates with git dependencies.
  2. `[patch.crates-io]` for `sd-jwt-payload` (fork making `Hasher` `Send + Sync`); patches do not
     propagate to consumers.
  3. `did-key = "0.2"` (issue #104), unmaintained, drags in `ed25519-dalek 1.x` and `curve25519-dalek 3.x`
     (two of the six ignored advisories).
  4. Internal path dependencies carry no `version` (PR #135 fixes this).
  5. Root `oid4vc` facade package with path-only deps (PR #135 sets `release = false`).

  identity-kit's `docs/DESIGN.md` states its purpose is to replace exactly these (`identity_*`,
  `did-key`, `sd-jwt-payload`) in openid4vc and ssi-agent. **The identity-kit migration is therefore
  the critical path to a first crates.io release**, not a nice-to-have.
- **Consumers:** `impierce/ssi-agent` consumes these crates by git rev. Renaming `dev` to `main`
  breaks any `branch = "dev"` reference there; a `rev = ...` pin keeps working. Check before renaming.
- **Dependencies likely flagged by `cargo deny` with `unmaintained = "all"`** (verify when running
  it): `derivative` (RUSTSEC-2024-0388), `paste` (RUSTSEC-2024-0436), plus the already ignored
  `did-key` chain, `h2 0.3` via `axum 0.6` / `wiremock 0.5`, `quick-xml` and `rsa 0.8` via `iota-sdk`.
  Also: `thiserror 1.0` vs 2.0, `jsonwebtoken 9.3` vs 10, `serde_with` pinned to `2.3` in
  `oid4vc-core` while the workspace says `3.0`, `lazy_static` where `std::sync::LazyLock` exists.
- **Tests:** 123 tests (`oid4vc-core` 17, `oid4vci` 34, `oid4vp` 58, `siopv2` 9, `oid4vc-manager` 5
  end-to-end flows over wiremock and an in-memory storage). Specification examples live as JSON in
  `oid4vci/tests/examples`, `oid4vp/tests/examples` and `oid4vc-manager/tests/common`. These are
  natural fuzz seeds.
- **Open work:** 23 open issues, most from 2023 (Presentation Exchange features, authorization code
  flow, docs). Open PRs: #93 (docs checklist, 2025), #124 (refactor `validate_credential_jwt`, April
  2026, external contributor), #135 (release pipeline, draft, yours).

### 1.3 PR #135 (`ci: add semantic release pipeline`) versus what identity-kit ended up with

PR #135 is a sound foundation but predates the identity-kit learnings. Differences to reconcile:

| Topic | PR #135 | identity-kit | Recommendation |
| --- | --- | --- | --- |
| Publish trigger | manual `workflow_dispatch` with per-crate checkboxes and `dry_run`, `release_always = true` | merging the release PR publishes, `release_always = false` | identity-kit model; keep `dry_run` as a separate `workflow_dispatch` input for rehearsals |
| Credentials | `CARGO_REGISTRY_TOKEN` secret, optional `RELEASE_PLZ_TOKEN` PAT | crates.io trusted publishing (OIDC) + `impierce-release-plz` GitHub App | identity-kit model. Caveat: trusted publishing cannot create a crate, so `oid4vc-core` and `oid4vc-manager` need one token-based first publish, then the trusted publisher is configured on crates.io |
| Tags | `{{ package }}-v{{ version }}` | `v{{ version }}` (single crate) | keep per-crate tags; the workspace releases crates independently |
| Version bumps | `features_always_increment_minor = true` because `!` is never used | standard Cargo semantics, `!` marks breaking changes | adopt `!` (enforced by the PR title check, documented in `CONTRIBUTING.md`) and drop the override |
| semver check | `semver_check = false` (no baseline) | on | off until the first release under the pipeline, then on; record in release-plz.toml as PR #135 already does |
| Changelog | one `CHANGELOG.md` per crate, Keep a Changelog header | one at root | per crate (release-plz default for workspaces) |
| Docs | `RELEASING.md` at root | `docs/RELEASE.md` + section in `CONTRIBUTING.md` | `docs/RELEASE.md`, port the excellent "Known blocker" section |
| Default branch | switches CI to `main`, states default branch changes | `main` | yes, as a separate, announced step |
| Actions | `@v6`, `@v0.5.136`, `@stable` | SHA-pinned | pin |

---

## 2. Target shape

```
openid4vc/
├── AGENTS.md                    # the single agent entry point (Claude Code reads it natively; no CLAUDE.md)
├── CONTRIBUTING.md  SECURITY.md  CHANGELOG.md (per crate, generated)
├── Cargo.toml  Cargo.lock       # lockfile committed
├── deny.toml  release-plz.toml  codecov.yml  rustfmt.toml  .coderabbit.yaml (optional)
├── .claude/
│   ├── settings.json            # enabledPlugins (local sessions only), hooks (SessionStart tooling)
│   └── skills/                  # repo-specific skills, committed (work in cloud sessions)
├── .github/
│   ├── CODEOWNERS  dependabot.yml  pull_request_template.md  ISSUE_TEMPLATE/
│   └── workflows/ qa.yml  coverage.yml  audit.yml  license.yml  fuzz.yml  pr-title.yml  release-plz.yml
├── docs/
│   ├── DESIGN.md  FEATURES.md  RELEASE.md
│   ├── adr/                     # decisions, numbered
│   └── agents/                  # issue-tracker.md  triage-labels.md  domain.md
├── fuzz/                        # own workspace, nightly, seeds from tests/examples
├── oid4vc-core/  oid4vci/  oid4vp/  siopv2/  oid4vc-manager/
└── (root `oid4vc` facade: decide, see §7)
```

Two facts from the Claude Code docs shape the agent layer (verified against
https://code.claude.com/docs/en/memory and https://code.claude.com/docs/en/cloud-environments):

1. Claude Code reads a root `AGENTS.md` natively **only when no `CLAUDE.md` exists**. So: one
   `AGENTS.md`, no `CLAUDE.md`. If Claude-only notes are ever needed, a `CLAUDE.md` whose first line
   is `@AGENTS.md` keeps one source of truth.
2. `enabledPlugins` in `.claude/settings.json` is **ignored in cloud sessions**; hooks and permission
   rules are read only when the session has a single repository. Anything that must work in a cloud
   session has to be a committed `.claude/skills/<name>/SKILL.md` or `.claude/agents/<name>.md`.
   The mattpocock-skills plugin and its `docs/agents/*.md` config therefore serve local sessions;
   the repo's own skills must be committed.

---

## 3. Phase A: agentic setup (done: PR 1 in §8)

Everything below is text and landed as one `docs:` PR on the default branch. The
sub-sections are kept as the record of what each file is for.

### A1. `AGENTS.md`

Model: identity-kit's, same section order, workspace-aware. Content to write:

- **Project**: what the workspace is; the five crates and their dependency order
  (`oid4vc-core → oid4vci → oid4vp → oid4vc-manager`, `oid4vc-core → siopv2 → oid4vc-manager`);
  which spec version each crate tracks (OID4VCI 1.0 final 2025-09-16, OID4VP 1.0 final 2025-07-09,
  SIOPv2 draft 13); pointers to `docs/DESIGN.md`, `docs/FEATURES.md`, `CONTRIBUTING.md`, issues
  labelled `ready-for-agent`, one PR per issue.
- **Ground rules** (derived from the code as it is, so agents keep it that way):
  - Wire types are `serde` structs mirroring the specification's JSON exactly; field names and
    optionality come from the spec section cited in the doc comment. Spec examples are the test
    oracle (`*/tests/examples/*.json`), never another implementation's output.
  - Extension points are traits (`Subject`, `Verifier`, `Validator`, `Storage`,
    `CredentialStatusVerifier`, `VerificationMaterialResolver`) and the `Extension`/`OpenID4VC`
    type-level mechanism in `oid4vc-core`; no closed enums of DID methods or key types.
  - Cargo features stay additive (`utoipa`, `test-utils`); `cargo clippy --workspace --all-targets
    --all-features -- -D warnings` clean; `rustfmt.toml` (`max_width = 120`) is law.
  - No new git or path dependencies outside the workspace; the existing ones are tracked for
    removal (identity-kit migration). Any advisory ignore needs a reason in `deny.toml` and, if it
    is a design choice, an ADR.
  - PR titles are Conventional Commits with `!` for breaking changes (squash merge); `feat` and
    `fix` scopes are crate names (`feat(oid4vp): ...`).
  - Never bump versions or edit changelogs by hand (release-plz, Phase C).
- **Workflow**: run the `CONTRIBUTING.md` checks locally before a PR; flip the `FEATURES.md` row
  in the implementing PR; record deviations from `DESIGN.md` as ADRs.
- **Agent skills**: the three sub-sections the mattpocock setup skill expects (issue tracker,
  triage labels, domain docs), each one line plus a pointer into `docs/agents/`.

### A2. `docs/agents/`

Copy identity-kit's three files and adjust:

- `issue-tracker.md`: GitHub, `gh` CLI, "PRs as a request surface: **yes**" is worth considering
  here (two stale external PRs, #93 and #124, are exactly what `/triage` would handle). Default to
  `no` like identity-kit unless you want them in the queue.
- `triage-labels.md`: same five roles. The labels do not exist on the repo yet; creating them is a
  one-time `gh label create` step (the plan does not do it).
- `domain.md`: the plugin renamed the glossary from `CONTEXT.md` to `GLOSSARY.md` (mattpocock/skills
  @ 49dd158, 2026-10-09). Write `GLOSSARY.md` here, and **fix identity-kit's `domain.md` and
  `AGENTS.md`, which still say `CONTEXT.md`** (small follow-up PR over there).

### A3. `docs/DESIGN.md`

An architecture document that matches the code, not an aspiration. Sections:

1. Principles (spec-mirroring types, traits for crypto/DID/storage, protocol logic free of I/O
   where possible, HTTP only in `oid4vc-manager` servers and the `reqwest` clients).
2. Crate map with responsibilities and the dependency order above.
3. `oid4vc-core` contracts: `Subject`/`Verifier`/`Validator`, `SubjectSyntaxType`, JWT helpers,
   `ClaimPathPointer`, the `Extension` mechanism and how `siopv2`/`oid4vp` plug into
   `AuthorizationRequest<E>`.
4. Per-protocol flows as implemented: OID4VCI (pre-authorized, authorization code, interactive
   authorization, nonce endpoint, notification), OID4VP (DCQL evaluation, VP token formats
   `jwt_vc_json`, `vc+sd-jwt`/`dc+sd-jwt`, clock skew), SIOPv2 (implicit flow, ID token).
5. The identity-kit migration: which `identity_*`/`did-key`/`sd-jwt-payload` touchpoints map to
   which identity-kit modules (`jose`, `resolver`, `vc`, `sd_jwt_vc`), and the order to migrate
   (`oid4vc-core` verifier and resolver first, then `oid4vp` token layer, then tests).
6. Conformance and CI (what Phase B enforces).

### A4. `docs/FEATURES.md`

Per protocol, one table like identity-kit's (Feature | Status | Cargo feature | Specification | Issue).
Seed it from the spec tables of contents and the existing modules; absorb the OID4VP checklist of
PR #93 rather than leaving that PR open; link the 2023 feature issues (#30, #31, #46, #7, #8, #4,
#32..#38) so they get a status instead of rotting.

### A5. `docs/adr/`

Start the log with the decisions this plan takes, so agents stop re-asking:

- `0001-independent-crate-versions.md`: per-crate versions, tags and changelogs (vs lockstep).
- `0002-facade-crate.md`: whether `oid4vc` (root) stays an unpublished facade, is published as an
  umbrella, or is removed (see §7).

The default branch (`main`) and the identity-kit migration were decided outside this plan and
have no ADR; the migration is tracked as Phase D work (§6) and in `docs/DESIGN.md`.

### A6. `CONTRIBUTING.md`, `SECURITY.md`, `.github/`

- `CONTRIBUTING.md`: identity-kit's, with workspace commands (`--workspace`), the title convention
  with crate scopes and `!`, the release pointer, the feature checklist rule.
- `SECURITY.md`: identity-kit's, with `openid4vc` URLs; "only the latest released version" needs a
  release first, phrase it accordingly.
- `.github/CODEOWNERS`: `* @daniel-mader @nanderstabel` (same as identity-kit; confirm).
- `.github/dependabot.yml`: identity-kit's. Needs the committed lockfile (Phase B) to be useful for
  cargo; the actions part works immediately.
- `.github/pull_request_template.md`: trim to "what / why / how tested" plus a reminder that the
  title is the changelog entry; the current checklist duplicates `CONTRIBUTING.md`.
- `.github/ISSUE_TEMPLATE/*.yml`: add `needs-triage` to the default labels of bug and suggestion
  templates once the label exists.
- `.coderabbit.yaml`: only if CodeRabbit reviews openid4vc too (exclude `tests/examples/**` and
  `fuzz/seeds/**`).

### A7. `.claude/`

- `.claude/settings.json`: `enabledPlugins: { "mattpocock-skills@claude-plugins-official": true }`
  for local sessions, plus a `SessionStart` hook (`startup|resume`) that runs
  `scripts/cloud-setup.sh` when `CLAUDE_CODE_REMOTE=true` to install `cargo-deny`, `cargo-llvm-cov`
  and `cargo-hack` (via `cargo-binstall` or `cargo install --locked`), so cloud agents can run the
  same checks CI runs. Rust itself is pre-installed in cloud sessions; this session had none of the
  cargo tools.
- `.claude/skills/` (committed, so they work in cloud sessions). Only where there is a repeatable
  repo procedure:
  - `spec-example-test/SKILL.md`: how to add a specification example as a test (file naming under
    `tests/examples`, the round-trip assertion pattern used in `oid4vci`/`oid4vp`, how to cite the
    spec section).
  - `pre-pr-checks/SKILL.md`: the exact command list from `CONTRIBUTING.md`, including the
    `--locked` and feature-matrix variants, and what to do when `cargo deny` fails.
  - Later, `fuzz-target/SKILL.md` (Phase B) and `release-dry-run/SKILL.md` (Phase C).
- No `.claude/agents/` initially; add one only if a recurring role emerges (for example a
  spec-conformance reviewer that reads the OID4VP text).

### A8. Repository settings (manual, by a maintainer; listed for completeness)

- Create the five triage labels.
- Branch protection on the default branch requiring the aggregate `QA` check (after Phase B).
- Decide on and install CodeRabbit, the `impierce-release-plz` GitHub App, and Codecov OIDC.

---

## 4. Phase B: CI hardening (second PR set)

Status: items 1 to 7 are done (PR 2 in §8) and item 8 is PR 3.

1. **Commit `Cargo.lock`** (`.gitignore` line removed). Enables `--locked`, reproducible CI, and
   Dependabot cargo PRs. This is a library workspace, but committing the lockfile is the current
   Cargo recommendation and what identity-kit does.
2. **`qa.yml`** modeled on identity-kit: fmt, clippy (`--workspace --all-targets --all-features
   --locked -D warnings`), test on ubuntu/macos/windows, rustdoc with `-D warnings`, MSRV from
   `rust-version` (`[workspace.package]`, `1.95` to match identity-kit; the committed lockfile
   needs at least `1.90`), aggregate `qa` job, and a `cargo hack --each-feature --workspace` job
   (cheap here: two features).
3. **`audit.yml` + `license.yml`** with `cargo-deny`, replacing `cargo audit` and `.cargo/audit.toml`.
   The six ignores were ported with their reasons into `deny.toml`; `unmaintained = "all"` added
   twelve more, all but two (`derivative`, `paste`, direct dependencies replaced in Phase D) from
   the `did-key` and `identity_*` trees, each ignored with a reason. Licenses outside the allow
   list (MPL-2.0, CC0-1.0, an LLVM exception, all in the iota-sdk tree) are per-crate exceptions;
   the ten git sources of that tree are allow-listed. `wildcards` stays at `warn` until the path
   dependencies carry versions (Phase C) and the git dependencies are gone.
4. **`coverage.yml`**: OIDC upload, `codecov.yml` informational, fork handling, `--workspace`.
5. **`pr-title.yml`**: `action-semantic-pull-request`, scopes optional, crate names suggested.
6. **Hygiene across workflows**: SHA-pinned actions, `permissions: contents: read`,
   `persist-credentials: false`, concurrency groups, `CARGO_TERM_COLOR`.
7. **Branch rename `dev` → `main`**: done. `main` is the default branch, the workflows run on `main`
   only, and `dev` is abandoned.
8. **`fuzz/`** (own workspace, nightly): targets for the parsers that take attacker-controlled
   input: credential offer (by value and by reference URL), authorization request (query string
   and JAR JWT), DCQL query and its evaluation against a credential set, token/credential/nonce
   responses, client metadata, `ClaimPathPointer`, VP token splitting. Seeds from
   `*/tests/examples`. Same `run.sh`, workflow and README as identity-kit.

---

## 5. Phase C: release process

Prerequisite: the publishing blockers in §1.2 are gone. The pipeline itself can be merged earlier
and exercised with `dry_run`; it will fail at `cargo publish` until then, which is a useful signal
(PR #135 already frames it this way).

1. **Supersede PR #135** with a PR rebased on this plan: keep its `release-plz.toml` structure,
   per-crate tags, `release = false` for the facade, versioned internal path deps, crate metadata
   (`description`, `keywords` ≤ 5, `repository`, `readme`, `include`, `[package.metadata.docs.rs]`).
   Change: `release_always = false`, trusted publishing with the `release` environment limited to
   `main`, GitHub App token for the release PR, standard bump semantics with `!`, `semver_check`
   off until first release, `docs/RELEASE.md` instead of `RELEASING.md`, SHA-pinned actions.
2. **First publish bootstrap**: `oid4vc-core` and `oid4vc-manager` do not exist on crates.io, and
   trusted publishing only works for existing crates. One manual `cargo publish` with a scoped
   token for those two, then configure the trusted publisher for all five, then the workflow takes
   over.
3. **Versions**: `oid4vci`/`oid4vp`/`siopv2` go from the 2023 `0.1.0` to `0.2.0` (breaking by any
   measure); `oid4vc-core` and `oid4vc-manager` start at `0.1.0` or join at `0.2.0` for a uniform
   first release (ADR 0001 decides). Afterwards release-plz bumps independently.
4. **Changelog** per crate, first entry summarising "everything since 0.1.0" by hand once (allowed
   before the pipeline owns the file), then generated.
5. **`CONTRIBUTING.md`/`AGENTS.md`** gain the "never bump by hand" rule the moment the pipeline merges.

---

## 6. Phase D: code hardening (ongoing, after A and B, each as a `ready-for-agent` issue)

- Workspace lints as in identity-kit (`unsafe_code = "forbid"`, `missing_docs = "warn"`,
  `unreachable_pub`, clippy `dbg_macro`/`todo`/`print_*`), then burn down the warnings per crate.
- `edition = "2024"` via `cargo fix --edition`, `thiserror 2`, `jsonwebtoken 10`, unify `serde_with`,
  `lazy_static` → `LazyLock`, `axum 0.8` and `wiremock 0.6` in `oid4vc-manager`, drop `derivative`
  and `paste`.
- Reduce `unwrap`/`expect` in `*/src` (395 today): the protocol parsers should return errors; the
  OID4VC error responses issue (#78) is the natural umbrella.
- identity-kit migration, file by file in the order of `docs/DESIGN.md` §5; each step
  removes one git dependency or advisory ignore.
- Triage the 2023 issue backlog with `/triage` into `ready-for-agent` / `ready-for-human` /
  `wontfix`, and close or merge #93 and #124.

---

## 7. Decisions taken (2026-10-18)

1. **Default branch**: `main` (done; `dev` is abandoned and no workflow runs on it).
2. **Versioning**: independent per-crate versions, tags and changelogs; first release `0.2.0` for
   all five ([ADR 0001](adr/0001-independent-crate-versions.md)).
3. **Root `oid4vc` facade crate**: kept, never released, `publish = false`
   ([ADR 0002](adr/0002-facade-crate.md)).
4. **PR #135**: superseded by the Phase C PR, which keeps its structure.
5. **External PRs in triage**: no (flag in `docs/agents/issue-tracker.md`).
6. **CodeRabbit**: already installed on the repository, so `.coderabbit.yaml` is in.
7. **MSRV**: `1.95`, the same as identity-kit (which is about to become a dependency); the
   committed lockfile needs at least `1.90`. Set in `[workspace.package] rust-version`.
8. **Labels**: identity-kit's five triage roles; the existing labels stay as categories. The five
   labels still have to be created on GitHub (`docs/agents/triage-labels.md` has the commands).

---

## 8. Suggested PR sequence

| # | Title (Conventional Commit) | Phase | Depends on | Status |
| --- | --- | --- | --- | --- |
| 1 | `docs: add agent setup, design document, feature checklist, ADRs and contributing guide` | A1–A7 | – | #139, merged |
| 2 | `ci: commit Cargo.lock, replace the workflows with QA, coverage, deny and PR title checks` | B1–B7 | 1 | #140 |
| 3 | `test: add cargo-fuzz targets seeded from specification examples` (with the `to_query_value` fix they found) | B8 | 2 | stacked on #140 |
| 4 | `ci: add release-plz pipeline with per-crate tags and trusted publishing` (supersedes #135) | C1 | 2 | |
| 5+ | Phase D issues, one PR each, `ready-for-agent` | D | 1–2 | |

Manual steps alongside PR 1 (A8): create the five triage labels, install nothing else yet.

Side PR on identity-kit: `docs: rename CONTEXT.md to GLOSSARY.md in agent docs`.

---

## Appendix: identity-kit observations made while comparing

- `docs/agents/domain.md` and `AGENTS.md` refer to `CONTEXT.md`; the plugin now uses `GLOSSARY.md`.
- `.claude/settings.json` only enables a plugin, which cloud sessions ignore; identity-kit has no
  committed skills, so cloud agents there rely on `AGENTS.md` alone. Fine today, worth knowing.
- `qa.yml` reads the MSRV with `select(.name == "identity-kit")`; the openid4vc variant should read
  `workspace.package.rust-version` or the first package's `rust_version` instead.
