# openid4vc: Design

`openid4vc` is a Cargo workspace of Rust libraries for the OpenID for Verifiable Credentials
(OpenID4VC) specification family of the
[OpenID Digital Credentials Protocols Working Group](https://openid.net/wg/digital-credentials-protocols/):
credential issuance (OID4VCI), presentation (OID4VP) and self-issued identity (SIOPv2). It is
published as **five crates** plus an unpublished facade. The main consumer is
[`impierce/ssi-agent`](https://github.com/impierce/ssi-agent) (UniCore).

This document describes the architecture as it is, so that changes can be judged against it. Where
the code falls short of the principles, the gap is named in [Known gaps](#known-gaps) rather than
papered over. Deviations from this document are recorded as ADRs in [`adr/`](adr/).

## Principles

1. **Wire types mirror the specification.** Every request, response and metadata document is a
   `serde` struct or enum whose field names, optionality and defaults follow the specification's
   JSON, with the spec section cited in the doc comment. Specification examples are the test
   oracle (`*/tests/examples/*.json`, inline vectors); no fixture of another implementation's
   output is ever committed.
2. **One request machinery, protocol-specific payloads.** `oid4vc-core` defines the generic
   OAuth-shaped `AuthorizationRequest` and `AuthorizationResponse`. SIOPv2 and OID4VP each plug
   their parameters and token logic in through the `Extension` trait, so parsing, signing (JAR) and
   sending a request is written once.
3. **Cryptography and identity behind traits.** Who signs (`Subject`, `Sign`, `ExternalSign`), how
   a key is found (`Verify`, identity-kit's `KeyResolver`), whether a credential is revoked
   (identity-kit's `StatusCheck`) and where an issuer keeps state (`Storage`) are traits. The
   library ships a `did:key` subject for development; vendor and method specific implementations
   live in consumers.
4. **Protocol logic free of I/O where it can be.** HTTP is confined to the `reqwest` clients
   (`oid4vci::Wallet`, `siopv2::Provider`, the client-metadata fetch in the extensions) and to
   `oid4vc-manager`'s `axum` issuer server. Parsing, validation and evaluation are pure functions
   over the wire types, which keeps them unit-testable and fuzzable.
5. **Additive features.** `utoipa` adds OpenAPI schemas to the wire types; `test-utils` adds test
   subjects. Everything builds with any combination.
6. **Specification versions are tracked explicitly.** The crate READMEs and
   [`FEATURES.md`](FEATURES.md) name the version each crate implements: OID4VCI 1.0 (final, 16
   September 2025), OID4VP 1.0 (final, 9 July 2025), SIOPv2 working group draft 13 (28 November
   2023), plus the OID4VCI Interactive Authorization draft.
7. **Publishable.** No git or path dependencies outside the workspace, versions and changelogs
   derived from Conventional Commits, `cargo publish --dry-run` green on every pull request. All
   but the versions and changelogs hold; those come with the release pipeline
   ([`PLAN.md`](PLAN.md), Phase C).

## Layout

```
openid4vc/
├── Cargo.toml                 # workspace + the `oid4vc` facade package (ADR 0002)
├── oid4vc-core/               # shared traits, request/response machinery, utilities
│   └── src/
│       ├── authentication/    # Sign, Verify, Subject, ExternalSign, Validator
│       ├── authorization_request.rs, authorization_response.rs
│       ├── openid4vc_extension.rs   # Extension, RequestHandle, ResponseHandle, OpenID4VC, Generic
│       ├── client_metadata.rs, scope.rs, subject_syntax_type.rs, rfc7519_claims.rs
│       ├── claim_path_pointer.rs    # JSON claim path pointer shared by OID4VCI and DCQL
│       ├── jwt.rs, utils/           # JWT encode/decode, form-urlencoded, DID kid normalisation
│       └── test_utils.rs            # [test-utils]
├── oid4vci/                   # OID4VCI 1.0 wire types, CredentialIssuer, Wallet client
│   └── src/
│       ├── credential_offer.rs, authorization_request.rs, authorization_details.rs, token_*.rs,
│       │   credential_request.rs, credential_response.rs, proof.rs, proofs.rs, nonce_response.rs,
│       │   notification_request.rs, interactive_authorization_*.rs, errors.rs
│       ├── credential_issuer/       # CredentialIssuer, issuer and authorization server metadata
│       ├── credential_format_profiles/   # jwt_vc_json, jwt_vc_json-ld, ldp_vc, mso_mdoc, dc+sd-jwt, vc+sd-jwt
│       └── wallet/                  # Wallet: the HTTP client side of every OID4VCI endpoint
├── oid4vp/                    # OID4VP 1.0: request parameters, DCQL, VP token
│   └── src/
│       ├── oid4vp.rs                # the OID4VP Extension
│       ├── authorization_request.rs # parameters, ClientId prefixes, verifier metadata
│       ├── dcql/, dcql_evaluation.rs
│       └── token/                   # VpToken, builders, VpTokenValidator
├── siopv2/                    # SIOPv2 draft 13: ID token, Provider, RelyingParty
├── oid4vc-manager/            # ProviderManager, RelyingPartyManager, CredentialIssuerManager, axum server
│   └── tests/                 # end-to-end flows: pre-authorized code, authorization code, SIOPv2, OID4VP
└── src/lib.rs                 # the facade: re-exports the five crates
```

Dependency order, which is also the publishing order:

```
oid4vc-core ──► oid4vci ──► oid4vp ──┐
      │                              ├──► oid4vc-manager ──► oid4vc (facade)
      └──────► siopv2 ───────────────┘
```

## `oid4vc-core`

### Authentication traits

```rust
pub trait Sign: Send + Sync {
    async fn key_id(&self, subject_syntax_type: &str, algorithm: Algorithm) -> Option<String>;
    async fn sign(&self, message: &str, subject_syntax_type: &str, algorithm: Algorithm) -> Result<Vec<u8>>;
    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>>;
}
pub trait Verify: Send + Sync {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
}
pub trait Subject: Sign + Verify + Send + Sync + Debug {
    async fn identifier(&self, subject_syntax_type: &str, algorithm: Algorithm) -> Result<String>;
}
pub type SigningSubject = Arc<dyn Subject>;
```

A `Subject` is a party that can identify itself (a DID or a JWK thumbprint, chosen by the
`SubjectSyntaxType` string), sign for that identifier and look up public keys by `kid`. `Sign`
asks for a *subject syntax type* and an *algorithm* on every call because one subject may hold
several keys (issue #76 added multi-algorithm support). `ExternalSign` lets a remote signer (HSM,
KMS, mobile secure element) perform the raw signature. `Validator` is an enum over `Arc<dyn
Subject>` or `Arc<dyn Verify>` with one job: `decode::<T>(jwt)`, which reads `kid` and `alg` from
the header, resolves the key and verifies.

`SubjectSyntaxType` is either `JwkThumbprint` (`urn:ietf:params:oauth:jwk-thumbprint`) or
`Did(DidMethod)`, where `DidMethod` carries an optional namespace (`did:iota:smr`, issue #75).

### The `Extension` mechanism

```rust
pub trait RequestHandle  { type Parameters; type Builder: Default; }
pub trait ResponseHandle { type Input; type Parameters; type ResponseItem; }

pub trait Extension: Serialize + ... {
    type RequestHandle: RequestHandle;
    type ResponseHandle: ResponseHandle;
    async fn generate_token(subject, client_id, request_parameters, user_input, syntax_type, alg) -> Result<Vec<String>>;
    async fn get_relying_party_supported_algorithms(request_parameters) -> Result<Vec<Algorithm>>;
    async fn get_relying_party_supported_syntax_types(request_parameters) -> Result<Vec<SubjectSyntaxType>>;
    fn build_authorization_response(jwts, user_input, redirect_uri, state) -> Result<AuthorizationResponse<Self>>;
    async fn decode_authorization_response(validator, response) -> Result<ResponseItem>;
}
pub trait OpenID4VC {}          // marker: an Extension that is a real protocol (SIOPv2, OID4VP)
pub struct Generic;              // Extension whose parameters are `serde_json::Value`
```

`AuthorizationRequest<B: Body>` is generic over how the request travels:

- `Object<E: Extension>`: the request object itself, `RFC7519Claims` + `client_id` +
  `redirect_uri`/`response_uri` + `state` + `E`'s parameters, all `#[serde(flatten)]`ed into one
  JSON object that is also what gets signed as a JAR request JWT.
- `ByValue { client_id, request }`: the `request=` JWT form.
- `ByReference { client_id, request_uri }`: the `request_uri=` form.

A request is first parsed as `AuthorizationRequest<Object<Generic>>` (any parameters), then
narrowed with `AuthorizationRequest::<Object<E>>::from_generic` once the protocol is known. Each
extension provides its own `Builder` type. `AuthorizationResponse<E>` carries `redirect_uri`,
`state` and `E`'s response parameters the same way. `ClientMetadataResource<T>` is the
by-value-or-by-URI client metadata, with `T` the protocol's metadata parameters and `other`
collecting unknown fields.

### Shared vocabulary

`Scope`/`ScopeValue` (OpenID Connect scopes), `RFC7519Claims` (`iss`, `sub`, `aud`, `exp`, `nbf`,
`iat`, `jti`), `ClaimPathPointer` (the JSON claims path of OID4VCI and DCQL, with
`get_values_from_json`), `StringOrObject`, `JsonObject`, the `builder_fn!` macro for builder
setters, `jwt::{encode, decode, extract_header}` over `jsonwebtoken`, and form-urlencoded helpers
that serialize nested objects as JSON strings the way the specs expect.

### Verification

Credentials and presentations are verified with identity-kit's three extension points: a
`resolver::KeyResolver` turns the key reference of a JWT into a public key (identity-kit's
`Resolver` with the DID methods a verifier accepts, `CompositeKeyResolver` to add keys by value or
the key sets of HTTPS issuers), a `jose::JwsVerifier` checks the signature (`DefaultVerifier`:
EdDSA, ES256, and ES256K with low `s` only), and a `vc::validation::StatusCheck` checks the
`credentialStatus` entries and `status` claims (`StatusListCheck` for the Token Status List).
`oid4vp`'s validator is generic over all three, so it is independent of any DID method or status
list implementation.

## `oid4vci`

Everything in OID4VCI 1.0 as data, plus the wallet side as a client. There is no issuer server in
this crate; `CredentialIssuer` holds the issuer's `Subject`, `CredentialIssuerMetadata` and
`AuthorizationServerMetadata` and validates proofs of possession. The server is in
`oid4vc-manager`.

- **Credential Offer**: `CredentialOffer` (by value or `credential_offer_uri`), rendered to and
  parsed from the `openid-credential-offer://` URL; `Grants` with `authorization_code`
  (`issuer_state`, `authorization_server`) and `pre-authorized_code` (`tx_code` constraints with
  input mode, length and description; `interval`).
- **Authorization**: `AuthorizationRequest` (response type, `authorization_details`, scope,
  `issuer_state`, PKCE) and `AuthorizationDetailsObject` (`openid_credential` with
  `credential_configuration_id`, `claims` as path pointers, `locations`,
  `credential_identifiers`). `Wallet` supports pushed authorization requests.
- **Interactive Authorization** (draft): `InteractiveAuthorizationRequest`, follow-up request and
  the response states (`redirect_to_web`, `require_presentation`, `authorization_code`, error).
- **Token**: `TokenRequest` tagged by `grant_type` (authorization code with PKCE verifier,
  pre-authorized code with `tx_code`), `TokenResponse` with `authorization_details`.
- **Nonce endpoint**: `NonceResponse`.
- **Credential**: `CredentialRequest` by `credential_identifier` or
  `credential_configuration_id`, `Proofs` (a batch of `jwt` proofs), `CredentialResponse` as
  immediate `credentials[]` + `notification_id` or deferred `transaction_id` + `interval`.
- **Notification**: `NotificationRequest` with the three events.
- **Metadata**: `CredentialIssuerMetadata` (`/.well-known/openid-credential-issuer`, including
  `credential_configurations_supported`, display, batch issuance, response encryption, signed
  metadata) and `AuthorizationServerMetadata` (`/.well-known/oauth-authorization-server`, with the
  PAR and interactive authorization extensions).
- **Credential format profiles**: a macro generates, per format, a marker type, a `Parameters`
  type (what issuer metadata and authorization details carry) and a `Credential` type (the issued
  credential); `CredentialFormats<C>` is the enum over `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`,
  `mso_mdoc`, `dc+sd-jwt` and the legacy `vc+sd-jwt`.
- **Errors**: `OID4VCError<T>` wraps the per-endpoint error enums (authorization, token,
  credential, deferred credential, notification, interactive authorization) with `ErrorStatusCode`
  giving each its HTTP status.
- **`Wallet`**: a `reqwest` client with retry middleware covering every endpoint above: fetch the
  offer, discover both metadata documents, PAR, authorize, token, nonce, credential (selecting the
  proof algorithm and subject syntax type the issuer supports), interactive authorization and
  follow-up, notification.
- **`utoipa`**: `ToSchema` on the wire types, tested against the generated OpenAPI document in
  `oid4vci/tests/openapi_schemas.rs`.

## `oid4vp`

OID4VP 1.0 with DCQL. Presentation Exchange is gone, as in the specification.

- **`OID4VP` extension**: `AuthorizationRequestParameters` with `response_type: vp_token`
  (enforced by `monostate::MustBe!`), `dcql_query`, `response_mode`, `nonce`, `scope`,
  `client_metadata`, `transaction_data`, `verifier_info`, `request_uri_method`. The extension
  reads the verifier's supported algorithms and subject syntax types from the client metadata
  (fetching it when given by URI) and builds the response from a `VpToken`.
- **Client identifier**: `ClientId` parses and prints the 1.0 prefixes (none for a pre-registered
  client, `redirect_uri`, `openid_federation`, `decentralized_identifier`, `verifier_attestation`,
  `x509_san_dns`, `x509_hash`).
- **Verifier metadata**: `ClientMetadataParameters` with `vp_formats_supported` per format
  (`jwt_vc_json`, `jwt_vp_json`, `dc+sd-jwt`, `vc+sd-jwt`, `ldp_vc`, `di_vp`, `mso_mdoc`),
  `jwks` and `encrypted_response_enc_values_supported`.
- **DCQL** (`dcql/`): `DcqlQuery` → `CredentialQuery` (`id`, `format`, `multiple`, `meta`,
  `trusted_authorities`, `require_cryptographic_holder_binding`, `claims`, `claim_sets`) and
  `CredentialSetQuery`. `meta` is an untagged enum over the W3C (`type_values`), SD-JWT VC
  (`vct_values`) and mdoc (`doctype_value`) shapes, validated against the format. `validate_all`
  enforces the specification's structural rules (unique ids, claim ids required when claim sets
  exist, set options referencing known queries). `dcql_evaluation` decides whether a decoded VP
  token satisfies a query: credential sets, per-query `meta` and claims, value matching.
- **VP token** (`token/`): `VpToken` is the map from credential query id to presentations
  (`StringOrObject`). `VpTokenBuilder` checks a submission against the query before building
  (required sets, unrequested ids). `VerifiablePresentationJwt` and its builder wrap a W3C
  presentation in the claims of a JWT: a VCDM 1.1 `identity_kit::vc::Presentation` of credential
  JWTs (`jwt_vc_json`) in the `vp` claim, or a VCDM 2.0 `PresentationV2` of enveloped credentials
  (`vc+sd-jwt`) as the payload itself, with `iss` the holder, `aud` and `nonce`. `VpTokenValidator<R, V>` takes identity-kit's `KeyResolver`, a
  `JwsVerifier` (`DefaultVerifier` unless given) and a `StatusCheck`, and validates `jwt_vc_json`,
  `dc+sd-jwt` and `vc+sd-jwt` presentations with identity-kit's `JwtPresentationValidator` and
  `SdJwtCredentialValidator`: presentation signature, `aud`/`nonce` (the SD-JWT key binding JWT's
  signature, `aud`, `nonce` and `sd_hash`), credential signatures, that every credential subject is
  the holder, validity dates with a configurable clock skew leeway (default 60 s), credential status
  (per a `StatusPolicy`, `SkipUnsupported` by default), and DCQL evaluation of the decoded result.
  A `vc+sd-jwt` presentation JWT may carry `typ: JWT` instead of `vp+jwt`, as `jwt::encode` signs
  it and as presentations built with `identity_credential` did.

## `siopv2`

SIOPv2 draft 13: the wallet acts as an OpenID Provider and issues ID tokens about itself.

- **`SIOPv2` extension**: `AuthorizationRequestParameters` with `response_type: id_token`,
  `scope`, `nonce`, `claims` (typed `ClaimRequests` for the standard OpenID Connect claims) and
  `client_metadata` with `subject_syntax_types_supported` and `id_token_signed_response_alg`.
  `generate_token` builds and signs the ID token (`iss == sub`, `aud` = client id, `nonce`, 10 min
  expiry, requested standard claims).
- **`IdToken`** and `IdTokenBuilder`; `StandardClaims<C>` is one generic struct for both the
  requested (`ClaimRequest`, with `essential`/`value`/`values`) and the asserted (`ClaimValue`)
  shape of the standard claims, including `Address`.
- **`Provider`** (wallet side): `validate_request` parses a request string (by value, by reference
  or object), fetching `request_uri` when needed and verifying the request JWT;
  `get_matching_signing_algorithm` / `get_matching_subject_syntax_type` intersect what the
  verifier accepts with what the wallet supports; `generate_response`; `send_response` posts the
  response (`direct_post`) or returns it for a redirect.
- **`RelyingParty`** (verifier side): `encode` signs an `AuthorizationRequest<Object<E>>` as a
  JWT; `validate_response` decodes the ID token. It is generic over `E`, which is how the
  `oid4vc-manager` flows reuse it for OID4VP requests.

## `oid4vc-manager`

Thin, opinionated wrappers plus the only server in the workspace:

- `ProviderManager` and `RelyingPartyManager` wrap `siopv2::Provider` / `RelyingParty` with
  the lists of supported algorithms and subject syntax types. `RelyingPartyManager::validate_response`
  is deprecated for OID4VP in favour of `VpTokenValidator`.
- `CredentialIssuerManager<S: Storage>` builds a `CredentialIssuer` whose metadata points at an
  `axum` `Server` with the routes `/.well-known/oauth-authorization-server`,
  `/.well-known/openid-credential-issuer`, `/credential_offer`, `/par`, `/authorize`, `/token`,
  `/credential`, `/notification`, plus an optional extension `Router`. `Storage` is the trait the
  server reads everything from (configurations, codes, token and credential responses, state).
- `methods::KeySubject` is the development `Subject`: `did:key` over an Ed25519 key in an
  identity-kit `KeyStore` (`InMemoryKeyStore` for `KeySubject::new`), signing through `KeySigner` or
  an optional `ExternalSign`. `methods::KeyValidator` (and `KeySubject`'s `Verify`) resolves the
  `kid` of a JWT to an Ed25519 or P-256 `did:key` key, for `EdDSA` and `ES256`; the `kid` must be a
  DID URL naming the key's verification method.
- `tests/` are the end-to-end flows: pre-authorized code (with and without batch and by-reference
  offer), authorization code, SIOPv2 implicit flow over `did:key` and a custom method, OID4VP
  implicit flow, all over `wiremock` and an in-memory `Storage`.

## Cross-cutting conventions

- **Serde**: `#[skip_serializing_none]` on wire structs, `#[serde(flatten)]` for composition,
  `#[serde(untagged)]` for one-of shapes, `MustBe!("vp_token")` for fixed values, newtypes with
  validation (`nutype`) for constrained strings. Unknown fields are kept where the spec allows
  extension (`other: JsonObject`) and otherwise ignored, serde's default; only `siopv2`'s standard
  claims use `deny_unknown_fields`.
- **Async**: `tokio`, `async-trait` on the object-safe traits, `impl Future` on `Extension`.
- **HTTP**: `reqwest` with `rustls` and the `ring` provider (`oid4vc_core::http_client`, as in
  identity-kit), `reqwest-middleware` + `reqwest-retry` (exponential backoff, five retries) on every client.
- **Errors**: `thiserror` enums where the type is new (`VpTokenValidationError`,
  `DcqlQueryError`, `OID4VCError<T>`); `anyhow::Result` on most older APIs (see Known gaps).
- **Tracing**: `tracing` spans and events on the public entry points (`#[tracing::instrument]`).
- **Features**: `utoipa` (`oid4vc-core`, `oid4vci`), `test-utils` (`oid4vc-core`). Both off by
  default.
- **Formatting**: `rustfmt.toml` with `max_width = 120`; clippy at `-D warnings`.

## Known gaps

Named so that work on them is deliberate, not accidental:

- **Error handling**: much of the public API returns `anyhow::Result`, and the crate code has
  several hundred `unwrap`/`expect` calls, some in parsing paths. Issue #78 (OID4VC error
  responses) is the umbrella for moving to typed errors that map to the specifications' error
  responses.
- **Validator coverage**: `VpTokenValidator` handles `jwt_vc_json`, `dc+sd-jwt` and `vc+sd-jwt`;
  `ldp_vc` and `mso_mdoc` return `UnsupportedFormat`. `trusted_authorities` are parsed but not
  verified: presentations for a query with them are rejected unless the verifier opts into
  `TrustedAuthoritiesPolicy::Ignore` (issue #191).
- **Response modes**: `direct_post` only; no JARM (`direct_post.jwt`), no encrypted responses, no
  Digital Credentials API transport.
- **SIOPv2**: the JWK thumbprint subject syntax type is parsed but no `Subject` produces it
  (issue #8); `client_metadata_uri` is not resolved for syntax types (TODO); draft 13 is old.
- **Signed metadata**: `signed_metadata` is carried but not verified.
- **Workspace-level lints absent** (`unsafe_code`, `missing_docs`, clippy `dbg_macro` and
  friends). Tracked in [`PLAN.md`](PLAN.md), Phase D.

### identity-kit migration map

Done; no `identity_*`, `did_url`, `did-key` or `sd-jwt-payload` code remains. DID syntax
(`DidMethod`'s conversion and the test subjects) uses `identity_kit::did::Did` instead of `did_url`, and
`KeySubject` uses `identity_kit::methods::key` and `keys::{InMemoryKeyStore, KeySigner}` instead of
`did-key`. `VpTokenValidator` validates with `identity_kit::vc::validation` and
`identity_kit::sd_jwt_vc`, over `resolver::KeyResolver`, `jose::JwsVerifier` and
`vc::validation::StatusCheck`, which replace `SignatureVerifier`, `VerificationMaterialResolver` and
`CredentialStatusVerifier`. `VerifiablePresentationJwt` carries `identity_kit::vc::{Presentation,
PresentationV2}` instead of `identity_credential`'s `Presentation<CRED>`.

## Conformance and CI

What CI enforces, and what [`PLAN.md`](PLAN.md) adds:

- Today (`.github/workflows/`): `qa.yml` with `cargo fmt --all --check`, clippy `-D warnings`, tests
  on Linux/macOS/Windows, the feature matrix (`cargo hack check --workspace --each-feature`),
  rustdoc with `-D warnings` and an MSRV build from `rust-version`, all `--locked` against the committed `Cargo.lock`, behind
  one aggregate `QA` check; `audit.yml` and `license.yml` with `cargo deny` (`deny.toml`: advisories
  daily and on manifest changes; licenses, bans and sources on manifest changes); `coverage.yml`
  via `cargo-llvm-cov` and Codecov (informational); `pr-title.yml` for the Conventional Commit
  title; `fuzz.yml` running the `cargo-fuzz` targets of `fuzz/` (seeded from `*/tests/examples`)
  for a minute per pull request and ten minutes nightly; and `cargo publish --dry-run --workspace`
  in QA, which packages and builds the five crates as crates.io would receive them.
- Release: `release-plz.yml` keeps a release pull request up to date and publishes on its merge
  ([`RELEASE.md`](RELEASE.md)).

## References

- OID4VCI 1.0: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- OID4VCI Interactive Authorization (draft, Digital Credentials Protocols WG): https://openid.net/wg/digital-credentials-protocols/specifications/
- OID4VP 1.0: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- SIOPv2 draft 13: https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html
- OAuth 2.0 Rich Authorization Requests (RFC 9396), Pushed Authorization Requests (RFC 9126),
  JWT-Secured Authorization Request (RFC 9101), PKCE (RFC 7636)
- SD-JWT (RFC 9901), SD-JWT VC: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- W3C VC Data Model 1.1 and 2.0, VC-JOSE-COSE
- identity-kit design: https://github.com/impierce/identity-kit/blob/main/docs/DESIGN.md
