# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/impierce/openid4vc/compare/oid4vp-v0.1.0...oid4vp-v0.2.0) - 2026-10-25

### Added

- *(oid4vp)* tolerate clock skew for presentations and credential dates ([#137](https://github.com/impierce/openid4vc/pull/137))
- expose protocol schemas with `utoipa` ([#136](https://github.com/impierce/openid4vc/pull/136))
- *(tracing)* add structured tracing instrumentation across workspace ([#134](https://github.com/impierce/openid4vc/pull/134))
- implement Interactive Authorization flow ([#127](https://github.com/impierce/openid4vc/pull/127))
- check `vct_values` during DCQL evaluation ([#130](https://github.com/impierce/openid4vc/pull/130))
- add vc+sd-jwt to vp_formats_supported ([#126](https://github.com/impierce/openid4vc/pull/126))
- add `CredentialStatusVerifier` trait ([#122](https://github.com/impierce/openid4vc/pull/122))
- enhance `VpToken` validation ([#121](https://github.com/impierce/openid4vc/pull/121))
- migrate OID4VCI and OID4VP to 1.0  ([#119](https://github.com/impierce/openid4vc/pull/119))
- update OpenID4VCI to Draft 15, support Authorization Code flow ([#106](https://github.com/impierce/openid4vc/pull/106))
- update `oid4vp` to draft 28 ([#98](https://github.com/impierce/openid4vc/pull/98))
- bootstrap SD-JWT support ([#82](https://github.com/impierce/openid4vc/pull/82))
- add support for multiple signing algorithms ([#76](https://github.com/impierce/openid4vc/pull/76))
- make trait methods in `oid4vc-core` async ([#74](https://github.com/impierce/openid4vc/pull/74))
- add support for using multiple DID methods ([#70](https://github.com/impierce/openid4vc/pull/70))
- update OpenID4VCI to WG Draft 13 ([#64](https://github.com/impierce/openid4vc/pull/64))
- update SIOPv2 to WG Draft 13 ([#61](https://github.com/impierce/openid4vc/pull/61))
- update OpenID4VP to WG Draft 20 ([#62](https://github.com/impierce/openid4vc/pull/62))
- add `Clone`, `Default`, `PartialEq` implementations to several types ([#65](https://github.com/impierce/openid4vc/pull/65))
- add `Extension` trait for `SIOPv2` and `OID4VP` ([#60](https://github.com/impierce/openid4vc/pull/60))
- initial VP support ([#21](https://github.com/impierce/openid4vc/pull/21))
- add monorepo ([#29](https://github.com/impierce/openid4vc/pull/29))

### Documentation

- add `AuthorizationRequest` comments ([#129](https://github.com/impierce/openid4vc/pull/129))
- add introductory documentation for all crates ([#57](https://github.com/impierce/openid4vc/pull/57))

### Fixed

- [**breaking**] fix various parser bugs and panics ([#163](https://github.com/impierce/openid4vc/pull/163))
- validate all Credentials and nonces in Authorization Response ([#115](https://github.com/impierce/openid4vc/pull/115))
- evaluate `meta` in DCQL query, handle error gracefully ([#109](https://github.com/impierce/openid4vc/pull/109))
- deprecate async-trait for the Sign trait ([#49](https://github.com/impierce/openid4vc/pull/49))
- fix keyword

### Other

- *(oid4vp)* [**breaking**] build presentation JWTs with IdentityKit ([#174](https://github.com/impierce/openid4vc/pull/174))
- *(oid4vp)* [**breaking**] validate VP tokens with IdentityKit ([#173](https://github.com/impierce/openid4vc/pull/173))
- [**breaking**] replace `derivative`, `paste` and `lazy_static` ([#171](https://github.com/impierce/openid4vc/pull/171))
- *(deps)* [**breaking**] update all dependencies to latest versions ([#164](https://github.com/impierce/openid4vc/pull/164))
- make credential format validators inside `vp_token_validator` public ([#133](https://github.com/impierce/openid4vc/pull/133))
- bump `identity_credential` to `v1.6.0-beta.7` ([#110](https://github.com/impierce/openid4vc/pull/110))
- support multiple did's and oid4vc-manager ([#28](https://github.com/impierce/openid4vc/pull/28))
