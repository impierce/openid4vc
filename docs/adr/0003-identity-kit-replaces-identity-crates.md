# ADR 0003: `identity-kit` replaces the `identity_*` crates, `sd-jwt-payload` and `did-key`

- Status: accepted
- Date: 2026-10-18

## Context

`oid4vc-core` and `oid4vp` depend on eight `identity_*` crates from `iotaledger/identity`
(`identity_did`, `identity_document`, `identity_core`, `identity_credential`, `identity_jose`,
`identity_verification`, `identity_ecdsa_verifier`, `identity_eddsa_verifier`) pinned to the git
tag `v1.9.6-beta.1`, which is not on crates.io. The workspace also patches `sd-jwt-payload` with a
fork that makes its `Hasher` trait `Send + Sync`, and uses the unmaintained `did-key` crate for the
development `did:key` subject and the test resolver (issue #104).

Consequences today:

- Cargo refuses to package a crate with git dependencies, and `[patch.crates-io]` does not reach
  consumers, so no crate in the workspace can be published to crates.io (pull request #135 documents
  this as the blocker of the release pipeline).
- Six advisories are ignored in `.cargo/audit.toml`; four of them (`ed25519-dalek 1.x`,
  `curve25519-dalek 3.x`, `quick-xml`, `rsa 0.8`) come in through `did-key` and the `identity_*`
  graph (`iota-sdk`).
- `cargo-semver-checks` and `cargo publish --dry-run` cannot run.

`impierce/identity-kit` exists for this purpose. Its design document names `openid4vc` and
`ssi-agent` as the consumers it replaces `identity_*`, Stronghold, `ssi-*`/`did-*` and `did-key`
for, it is published on crates.io, and it covers what this workspace uses: DIDs and DID documents,
JWK and compact JWS with EdDSA/ES256/ES256K/RSA verification, a `DidResolver` registry with
`did:key`, `did:jwk` and `did:web`, a `KeyStore` trait with in-memory and file backends, VC/VP as
JWTs (VCDM 1.1 and 2.0), SD-JWT and SD-JWT VC with status lists and type metadata.

## Decision

1. Replace the `identity_*` crates, the `sd-jwt-payload` patch and `did-key` with `identity-kit`,
   as a crates.io dependency (never git).
2. Migrate in dependency order, one pull request per step, each removing at least one git
   dependency or advisory ignore and keeping the end-to-end tests green:
   1. `oid4vc-core`: `SignatureVerifier` → `identity_kit::jose::JwsVerifier` /
      `DefaultVerifier`; `VerificationMaterialResolver` over `identity_kit::did::{Did, DidUrl,
      DidDocument}` and `identity_kit::jose::Jwk`; `utils::did` over `DidUrl`.
   2. `oid4vp`: the VP token validator and presentation JWT builder over `identity_kit::vc` and
      `identity_kit::sd_jwt_vc`; drop the `sd-jwt-payload` patch.
   3. `oid4vc-manager`: `KeySubject` and the `test-utils` resolver over `identity_kit::methods::key`
      and `identity_kit::keys` (`InMemoryKeyStore` for tests, `SoftwareKeyStore` for development).
   4. Remove the ignores in `.cargo/audit.toml` that no longer apply.
3. Gaps found in `identity-kit` during the migration are fixed in `identity-kit` (its
   `docs/FEATURES.md` tracks them), not worked around here. Until a gap is closed, the affected
   step waits; no new `identity_*` usage is added meanwhile.
4. `jsonwebtoken` stays for the OpenID-level JWTs (request objects, ID tokens, proofs) unless the
   migration shows that `identity_kit::jose` covers them with less code.

## Consequences

- Publishing becomes possible; the release pipeline (`docs/PLAN.md`, Phase C) can go live after
  step 2 for `oid4vc-core`, `oid4vci`, `oid4vp` and `siopv2`, and after step 3 for `oid4vc-manager`.
- The public API of `oid4vc-core` and `oid4vp` changes where `identity_*` types were exposed
  (`CoreDID`, `CoreDocument`, `Jwk`, `JwsVerifier`); these are `!` changes and bump the minor
  version (ADR 0002).
- `ssi-agent`, which consumes both repositories, migrates alongside; its pins move from branch or
  revision references to crates.io versions once releases exist.
