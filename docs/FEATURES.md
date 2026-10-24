# Features

Everything `openid4vc` implements or plans to implement, per specification. The architecture
behind the list is in [`DESIGN.md`](DESIGN.md). Tick a row off in the pull request that
implements it; open an issue and link it when you start planning a row.

| Status | Meaning                                                 |
| ------ | ------------------------------------------------------- |
| ✅     | Implemented on the default branch, covered by tests     |
| 🚧     | Partial: the type exists but the behaviour is incomplete |
| 📋     | Planned, issue open                                     |
| ⬜     | Not implemented, no issue yet                           |
| ➖     | Out of scope (removed from the spec, or not planned)    |

Specification versions tracked: [OID4VCI 1.0][oid4vci] (final, 16 September 2025),
[OID4VP 1.0][oid4vp] (final, 9 July 2025), [SIOPv2 draft 13][siopv2] (28 November 2023),
[OID4VCI Interactive Authorization][oid4vci-ia] (draft).

## `oid4vc-core`

| Feature                                                                                  | Status | Cargo feature | Specification                               | Issue |
| ---------------------------------------------------------------------------------------- | :----: | ------------- | ------------------------------------------- | ----- |
| `Sign`, `Verify`, `Subject`, `ExternalSign` traits; `Validator` decoding JWTs by `kid`   |   ✅   |               | [RFC 7515][rfc7515], [RFC 7519][rfc7519]    |       |
| Multiple signing algorithms per subject (`algorithm` on every `Sign` call)               |   ✅   |               |                                             | [#76](https://github.com/impierce/openid4vc/pull/76) |
| `SubjectSyntaxType`: DID methods with optional namespace, JWK thumbprint                 |   ✅   |               | [SIOPv2, Relying Party Registration Metadata][siopv2], [RFC 7638][rfc7638]  | [#75](https://github.com/impierce/openid4vc/pull/75) |
| `AuthorizationRequest<Body>`: object, by value (`request`), by reference (`request_uri`) |   ✅   |               | [RFC 9101][rfc9101]                         |       |
| `Extension` / `RequestHandle` / `ResponseHandle` plug-in mechanism, `Generic` fallback   |   ✅   |               |                                             |       |
| `AuthorizationResponse<E>`, `ClientMetadataResource<T>` (by value or URI)                |   ✅   |               |                                             |       |
| `Scope`, `RFC7519Claims`, `StringOrObject`, `builder_fn!`                                |   ✅   |               | [RFC 7519][rfc7519]                         |       |
| `ClaimPathPointer` with `get_values_from_json` (arrays, nulls)                           |   ✅   |               | [OID4VP 1.0, Claims Path Pointer][oid4vp]   |       |
| Form-urlencoded helpers (nested objects as JSON strings)                                  |   ✅   |               |                                             |       |
| `test-utils`: test subjects                                                              |   ✅   | `test-utils`  |                                             |       |
| OpenAPI schemas for the shared types                                                     |   ✅   | `utoipa`      |                                             | [#132](https://github.com/impierce/openid4vc/pull/132) |
| Typed errors instead of `anyhow` on the public API                                       |   📋   |               |                                             | [#78](https://github.com/impierce/openid4vc/issues/78) |
| `const` strings for the supported specification versions                                 |   📋   |               |                                             | [#77](https://github.com/impierce/openid4vc/issues/77) |

## `oid4vci`: OpenID for Verifiable Credential Issuance 1.0

### Credential Offer

| Feature                                                                      | Status | Cargo feature | Specification                                | Issue |
| ---------------------------------------------------------------------------- | :----: | ------------- | -------------------------------------------- | ----- |
| Credential Offer by value and by reference (`credential_offer_uri`)          |   ✅   |               | [OID4VCI, Credential Offer Endpoint][oid4vci]      |       |
| `openid-credential-offer://` URL rendering and parsing                       |   ✅   |               | [OID4VCI, Credential Offer Endpoint][oid4vci]                        |       |
| `authorization_code` grant: `issuer_state`, `authorization_server`           |   ✅   |               | [OID4VCI, Credential Offer Parameters][oid4vci]                    |       |
| `pre-authorized_code` grant: `tx_code` constraints, `interval`               |   ✅   |               | [OID4VCI, Credential Offer Parameters][oid4vci]                    |       |
| Wallet fetches an offer by reference                                         |   ✅   |               | [OID4VCI, Sending Credential Offer by Reference][oid4vci]                    |       |

### Authorization

| Feature                                                                                      | Status | Cargo feature | Specification                                | Issue |
| -------------------------------------------------------------------------------------------- | :----: | ------------- | -------------------------------------------- | ----- |
| Authorization Request with `authorization_details` (`openid_credential`), `scope`, `issuer_state` |   ✅   |               | [OID4VCI, Authorization Request][oid4vci], [RFC 9396][rfc9396] |       |
| PKCE (`S256`)                                                                                |   ✅   |               | [RFC 7636][rfc7636]                          |       |
| Pushed Authorization Requests (wallet client and manager `/par` route)                        |   ✅   |               | [RFC 9126][rfc9126]                          |       |
| Authorization Code flow end to end (manager test)                                            |   ✅   |               | [OID4VCI, Authorization Code Flow][oid4vci]                      | [#46](https://github.com/impierce/openid4vc/issues/46), [#7](https://github.com/impierce/openid4vc/issues/7) |
| Dynamic Credential Request (presentation during issuance)                                    |   ⬜   |               | [OID4VCI, Dynamic Credential Request][oid4vci]                    |       |
| Interactive Authorization request, follow-up and response states                             |   ✅   |               | [Interactive Authorization draft][oid4vci-ia] | [#127](https://github.com/impierce/openid4vc/pull/127) |
| Authorization error responses                                                                |   ✅   |               | [OID4VCI, Authorization Error Response][oid4vci]                      | [#78](https://github.com/impierce/openid4vc/issues/78) |

### Token, Nonce, Credential, Deferred, Notification

| Feature                                                                                 | Status | Cargo feature | Specification                                  | Issue |
| --------------------------------------------------------------------------------------- | :----: | ------------- | ---------------------------------------------- | ----- |
| Token Request for both grants, `tx_code`; Token Response with `authorization_details`   |   ✅   |               | [OID4VCI, Token Endpoint][oid4vci]                          |       |
| Token error responses                                                                   |   ✅   |               | [OID4VCI, Token Error Response][oid4vci]                        |       |
| Nonce endpoint (`NonceResponse`, wallet client)                                         |   ✅   |               | [OID4VCI, Nonce Endpoint][oid4vci]                          |       |
| Credential Request by `credential_identifier` or `credential_configuration_id`          |   ✅   |               | [OID4VCI, Credential Request][oid4vci]                        |       |
| `jwt` key proof: build, sign, validate (`CredentialIssuer::validate_proofs`)            |   ✅   |               | [OID4VCI, Key Proof Types: `jwt`][oid4vci]                    |       |
| Batch issuance: multiple proofs, `batch_credential_issuance` metadata                   |   ✅   |               | [OID4VCI, Credential Request; Credential Issuer Metadata][oid4vci]               |       |
| `di_vp` and `attestation` key proof types, key attestations                             |   ⬜   |               | [OID4VCI, Key Proof Types][oid4vci]                      |       |
| Credential Response: immediate `credentials[]`, `notification_id`, deferred `transaction_id` |   ✅   |               | [OID4VCI, Credential Response][oid4vci]                        |       |
| Credential Response encryption (metadata type only, no JWE)                             |   🚧   |               | [OID4VCI, Credential Response Encryption][oid4vci]               |       |
| Credential error responses                                                              |   ✅   |               | [OID4VCI, Credential Error Response][oid4vci]                        |       |
| Deferred Credential endpoint (error types exist; no request/response or client)         |   🚧   |               | [OID4VCI, Deferred Credential Endpoint][oid4vci]                          |       |
| Notification endpoint: request type, wallet client, manager route                       |   ✅   |               | [OID4VCI, Notification Endpoint][oid4vci]                         |       |

### Metadata and formats

| Feature                                                                                       | Status | Cargo feature | Specification                              | Issue |
| --------------------------------------------------------------------------------------------- | :----: | ------------- | ------------------------------------------ | ----- |
| Credential Issuer Metadata (`/.well-known/openid-credential-issuer`), `credential_configurations_supported`, display, claims descriptions |   ✅   |               | [OID4VCI, Credential Issuer Metadata][oid4vci]                   |       |
| `signed_metadata` verification                                                                |   🚧   |               | [OID4VCI, Signed Metadata][oid4vci]                 |       |
| Authorization Server Metadata (`/.well-known/oauth-authorization-server`), PAR and interactive authorization extensions |   ✅   |               | [OID4VCI, Authorization Server Metadata][oid4vci], [RFC 8414][rfc8414] |       |
| Wallet / client metadata                                                                      |   ⬜   |               | [OID4VCI, Client Metadata][oid4vci]                   |       |
| Format profiles: `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`                                    |   ✅   |               | [OID4VCI, Credential Format Profiles: W3C][oid4vci]            |       |
| Format profile `mso_mdoc`                                                                     |   ✅   |               | [OID4VCI, Credential Format Profiles: ISO mdoc][oid4vci]            |       |
| Format profiles `dc+sd-jwt`, legacy `vc+sd-jwt`                                               |   ✅   |               | [OID4VCI, Credential Format Profiles: SD-JWT VC][oid4vci]            | [#126](https://github.com/impierce/openid4vc/pull/126) |
| Wallet attestation, DPoP                                                                      |   ⬜   |               | [OID4VCI, Security Considerations][oid4vci]           |       |
| `Wallet` client covering every endpoint, with retry middleware                                |   ✅   |               |                                            |       |
| OpenAPI schemas, tested against the generated document                                        |   ✅   | `utoipa`      |                                            | [#136](https://github.com/impierce/openid4vc/pull/136) |

## `oid4vp`: OpenID for Verifiable Presentations 1.0

### Authorization Request

| Feature                                                                                 | Status | Cargo feature | Specification                                     | Issue |
| --------------------------------------------------------------------------------------- | :----: | ------------- | ------------------------------------------------- | ----- |
| `response_type=vp_token`, `nonce`, `state`, `response_mode`                             |   ✅   |               | [OID4VP, Authorization Request][oid4vp]                               |       |
| `dcql_query` parameter                                                                  |   ✅   |               | [OID4VP, Authorization Request Parameters][oid4vp]                             |       |
| `client_metadata` by value; verifier metadata types per format, `jwks`, encryption enc values |   ✅   |               | [OID4VP, Verifier Metadata][oid4vp]                         |       |
| `transaction_data`, `verifier_info`, `request_uri_method` parameters (types)            |   🚧   |               | [OID4VP, Authorization Request Parameters][oid4vp]                             |       |
| Request by value (`request`) and by reference (`request_uri`), signed request (JAR)     |   ✅   |               | [OID4VP, Authorization Request][oid4vp], [RFC 9101][rfc9101]        |       |
| `request_uri_method=post`, `wallet_metadata`, `wallet_nonce`                            |   ⬜   |               | [OID4VP, Request URI Method `post`][oid4vp]                            |       |
| Requesting credentials with `scope`                                                     |   ⬜   |               | [OID4VP, Using `scope` to Request Credentials][oid4vp]                             |       |
| Client Identifier prefixes: parse and print all seven (`redirect_uri` is spelled `response_uri`, see `DESIGN.md`) |   🚧   |               | [OID4VP, Client Identifier Prefix][oid4vp]                             |       |
| Client identifier verification per prefix (DID via resolver only; x509, federation, attestation missing) |   🚧   |               | [OID4VP, Client Identifier Prefix][oid4vp]                             |       |
| Cross-device flow (request by reference behind a QR code)                               |   ✅   |               | [OID4VP, Same Device and Cross Device Flow][oid4vp]                               |       |
| Same-device flow with redirect and error response                                       |   📋   |               | [OID4VP, Same Device and Cross Device Flow][oid4vp]                               | [#40](https://github.com/impierce/openid4vc/issues/40) |
| Presentation Exchange (`presentation_definition`)                                       |   ➖   |               | removed in OID4VP 1.0                             | [#80](https://github.com/impierce/openid4vc/issues/80), [#32](https://github.com/impierce/openid4vc/issues/32)–[#38](https://github.com/impierce/openid4vc/issues/38) |

### DCQL

| Feature                                                                                       | Status | Cargo feature | Specification                      | Issue |
| --------------------------------------------------------------------------------------------- | :----: | ------------- | ---------------------------------- | ----- |
| `CredentialQuery`: `id`, `format`, `multiple`, `meta`, `trusted_authorities`, `require_cryptographic_holder_binding`, `claims`, `claim_sets` |   ✅   |               | [OID4VP, DCQL: Credential Query][oid4vp]              |       |
| `credential_sets` with `options` and `required`                                               |   ✅   |               | [OID4VP, DCQL: Credential Set Query][oid4vp]              |       |
| `meta` per format: W3C `type_values`, SD-JWT VC `vct_values`, mdoc `doctype_value`            |   ✅   |               | [OID4VP, DCQL: Credential Query][oid4vp]              | [#130](https://github.com/impierce/openid4vc/pull/130) |
| Claims queries with path pointers and `values` matching                                       |   ✅   |               | [OID4VP, DCQL: Claims Query, Claims Path Pointer][oid4vp]        |       |
| Structural validation rules (unique ids, claim ids with claim sets, set option references)    |   ✅   |               | [OID4VP, DCQL][oid4vp]                |       |
| Query evaluation against a decoded VP token (sets, meta, claims)                              |   ✅   |               | [OID4VP, DCQL: Selecting Claims and Credentials][oid4vp]            |       |
| `multiple` and `trusted_authorities` enforced during evaluation                               |   🚧   |               | [OID4VP, DCQL: Credential Query, Trusted Authorities][oid4vp]      |       |
| Specification examples as tests (`tests/examples/query_lang/`)                                |   ✅   |               | [OID4VP, DCQL][oid4vp]                |       |

### Response and VP Token

| Feature                                                                                  | Status | Cargo feature | Specification                            | Issue |
| ---------------------------------------------------------------------------------------- | :----: | ------------- | ---------------------------------------- | ----- |
| `VpToken` keyed by credential query id; builder validating the submission                |   ✅   |               | [OID4VP, Response: VP Token][oid4vp]                    |       |
| `direct_post` response mode (sending in `Provider::send_response`)                       |   ✅   |               | [OID4VP, Response Mode `direct_post`][oid4vp]                    |       |
| `direct_post.jwt` (JARM), encrypted responses                                            |   ⬜   |               | [OID4VP, Response Mode `direct_post.jwt`][oid4vp]                    |       |
| Transaction data in the response                                                         |   ⬜   |               | [OID4VP, Transaction Data][oid4vp]                    |       |
| Error responses                                                                          |   📋   |               | [OID4VP, Error Response][oid4vp]                    | [#78](https://github.com/impierce/openid4vc/issues/78) |
| `VpTokenValidator`: `jwt_vc_json` presentations and credentials                          |   ✅   |               | [OID4VP, Credential Format Specific Parameters: W3C][oid4vp]            |       |
| `VpTokenValidator`: `dc+sd-jwt` and `vc+sd-jwt`, key binding JWT                         |   ✅   |               | [OID4VP, Credential Format Specific Parameters: SD-JWT VC][oid4vp], [SD-JWT VC][sd-jwt-vc] |       |
| `VpTokenValidator`: `ldp_vc`, `mso_mdoc`                                                 |   ⬜   |               | [OID4VP, Credential Format Specific Parameters: `ldp_vc`, mdoc][oid4vp]     |       |
| Credential validity dates with configurable clock skew leeway                            |   ✅   |               |                                          | [#137](https://github.com/impierce/openid4vc/pull/137) |
| Credential status check through identity-kit's `StatusCheck`                             |   ✅   |               |                                          | [#165](https://github.com/impierce/openid4vc/issues/165) |
| Relative `kid` resolution against `iss`                                                  |   ✅   |               |                                          | [#165](https://github.com/impierce/openid4vc/issues/165) |
| VP token replay prevention guidance (nonce binding is enforced; storage is the caller's) |   ✅   |               | [OID4VP, Security Considerations][oid4vp]                     |       |
| OpenID4VP over the Digital Credentials API                                               |   ⬜   |               | [OID4VP, OpenID4VP over the Digital Credentials API][oid4vp]              |       |

## `siopv2`: Self-Issued OpenID Provider v2 (draft 13)

| Feature                                                                                  | Status | Cargo feature | Specification                      | Issue |
| ---------------------------------------------------------------------------------------- | :----: | ------------- | ---------------------------------- | ----- |
| Authorization Request: `response_type=id_token`, `scope`, `nonce`, `claims`, `client_metadata` |   ✅   |               | [SIOPv2, Self-Issued OpenID Provider Request][siopv2]                |       |
| Cross-device request detection (`response_mode=post`)                                    |   ✅   |               | [SIOPv2, Self-Issued OpenID Provider Request][siopv2]                |       |
| Client metadata: `subject_syntax_types_supported`, `id_token_signed_response_alg`        |   ✅   |               | [SIOPv2, Relying Party Registration Metadata][siopv2]              |       |
| `client_metadata_uri` resolution for subject syntax types                                |   🚧   |               | [SIOPv2, Relying Party Registration Metadata][siopv2]              |       |
| ID Token build, sign and decode (`iss == sub`, `aud`, `nonce`, `exp`, `iat`)             |   ✅   |               | [SIOPv2, Self-Issued ID Token][siopv2]               | [#30](https://github.com/impierce/openid4vc/issues/30) |
| Standard claims: typed requests (`essential`, `value`, `values`) and values, `Address`   |   ✅   |               | [OIDC Core, Standard Claims; Requesting Claims][oidc]       | [#4](https://github.com/impierce/openid4vc/issues/4) |
| `sub_jwk` type                                                                           |   ✅   |               | [SIOPv2, Self-Issued ID Token][siopv2]               |       |
| JWK thumbprint subject syntax type produced by a `Subject`                               |   📋   |               | [SIOPv2, Relying Party Registration Metadata][siopv2]              | [#8](https://github.com/impierce/openid4vc/issues/8) |
| `Provider`: validate request, match algorithm and syntax type, generate and send response |   ✅   |               | [SIOPv2, Self-Issued OpenID Provider Response][siopv2]               |       |
| `RelyingParty`: sign request objects (JAR), validate ID token responses                  |   ✅   |               | [SIOPv2, Request and ID Token Validation][siopv2]           |       |
| Implicit flow end to end over `did:key` and a custom DID method (manager test)           |   ✅   |               |                                    |       |
| Static configuration values (discovery without a server)                                 |   📋   |               | [SIOPv2, Static Discovery Metadata][siopv2]            | [#47](https://github.com/impierce/openid4vc/issues/47) |
| Combined `vp_token id_token` response type                                               |   ⬜   |               | [OID4VP, Response Type `vp_token id_token`][oid4vp]              |       |
| ID Token feature completeness (remaining optional claims, `acr`/`amr` semantics)         |   📋   |               | [SIOPv2, Self-Issued ID Token][siopv2]               | [#20](https://github.com/impierce/openid4vc/issues/20) |

## `oid4vc-manager`

| Feature                                                                                   | Status | Cargo feature | Specification | Issue |
| ----------------------------------------------------------------------------------------- | :----: | ------------- | ------------- | ----- |
| `ProviderManager`, `RelyingPartyManager` over `siopv2`, generic in the `Extension`         |   ✅   |               |               |       |
| `CredentialIssuerManager<S: Storage>` with offers by value and by reference                |   ✅   |               |               |       |
| `axum` issuer server: metadata, offer, PAR, authorize, token, credential, notification routes, extension router |   ✅   |               |               |       |
| `Storage` trait                                                                            |   ✅   |               |               |       |
| `KeySubject` (`did:key`, Ed25519, any identity-kit `KeyStore`) with optional `ExternalSign` |   ✅   |               |               |       |
| `KeyValidator`: `did:key` Ed25519 (`EdDSA`) and P-256 (`ES256`) keys, `kid` naming the verification method |   ✅   |               |               |       |
| Replace `did-key` (unmaintained) with `identity-kit`                                       |   ✅   |               |               | [#104](https://github.com/impierce/openid4vc/issues/104), [`PLAN.md`](PLAN.md) Phase D |
| End-to-end tests: pre-authorized code (batch, by reference), authorization code, SIOPv2, OID4VP |   ✅   |               |               |       |
| Nonce and deferred credential routes                                                      |   ⬜   |               |               |       |

## Repository

| Feature                                                              | Status | Where                                         |
| -------------------------------------------------------------------- | :----: | --------------------------------------------- |
| Agent guidelines, design document, feature checklist, ADRs           |   ✅   | `AGENTS.md`, `docs/`                          |
| Committed lockfile, `--locked` CI, MSRV, multi-OS tests, rustdoc check |   ✅   | `.github/workflows/qa.yml`                    |
| `cargo deny` (advisories, licenses, bans, sources)                   |   ✅   | `deny.toml`, `.github/workflows/{audit,license}.yml` |
| Fuzz targets over the parsers, seeded from the spec examples         |   ✅   | [`fuzz/`](../fuzz/README.md), `.github/workflows/fuzz.yml` |
| Default branch `main`                                                |   ✅   | GitHub repository settings                    |
| release-plz with per-crate versions, trusted publishing              |   🚧   | [`RELEASE.md`](RELEASE.md), [ADR 0001](adr/0001-independent-crate-versions.md); the first release is pending |
| Publishable: no git dependencies, no patches, `cargo publish --dry-run` in CI |   ✅   | `.github/workflows/qa.yml`, `deny.toml` |

[oid4vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[oid4vci-ia]: https://openid.net/wg/digital-credentials-protocols/specifications/
[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[siopv2]: https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html
[oidc]: https://openid.net/specs/openid-connect-core-1_0.html
[sd-jwt-vc]: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519
[rfc7636]: https://www.rfc-editor.org/rfc/rfc7636
[rfc7638]: https://www.rfc-editor.org/rfc/rfc7638
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037
[rfc8414]: https://www.rfc-editor.org/rfc/rfc8414
[rfc9101]: https://www.rfc-editor.org/rfc/rfc9101
[rfc9126]: https://www.rfc-editor.org/rfc/rfc9126
[rfc9396]: https://www.rfc-editor.org/rfc/rfc9396
