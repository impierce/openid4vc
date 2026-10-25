# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/impierce/openid4vc/releases/tag/oid4vc-manager-v0.2.0) - 2026-10-25

### Added

- expose protocol schemas with `utoipa` ([#136](https://github.com/impierce/openid4vc/pull/136))
- *(tracing)* add structured tracing instrumentation across workspace ([#134](https://github.com/impierce/openid4vc/pull/134))
- check `vct_values` during DCQL evaluation ([#130](https://github.com/impierce/openid4vc/pull/130))
- add `CredentialStatusVerifier` trait ([#122](https://github.com/impierce/openid4vc/pull/122))
- enhance `VpToken` validation ([#121](https://github.com/impierce/openid4vc/pull/121))
- migrate OID4VCI and OID4VP to 1.0  ([#119](https://github.com/impierce/openid4vc/pull/119))
- update OpenID4VCI to Draft 15, support Authorization Code flow ([#106](https://github.com/impierce/openid4vc/pull/106))
- update `oid4vp` to draft 28 ([#98](https://github.com/impierce/openid4vc/pull/98))
- require `Debug` supertrait for `ExternalSign` and `Subject` ([#97](https://github.com/impierce/openid4vc/pull/97))
- add `NotificationRequest` struct
- bootstrap SD-JWT support ([#82](https://github.com/impierce/openid4vc/pull/82))
- add support for multiple signing algorithms ([#76](https://github.com/impierce/openid4vc/pull/76))
- make trait methods in `oid4vc-core` async ([#74](https://github.com/impierce/openid4vc/pull/74))
- add support for using multiple DID methods ([#70](https://github.com/impierce/openid4vc/pull/70))
- update OpenID4VCI to WG Draft 13 ([#64](https://github.com/impierce/openid4vc/pull/64))
- update SIOPv2 to WG Draft 13 ([#61](https://github.com/impierce/openid4vc/pull/61))
- update OpenID4VP to WG Draft 20 ([#62](https://github.com/impierce/openid4vc/pull/62))
- add `Clone`, `Default`, `PartialEq` implementations to several types ([#65](https://github.com/impierce/openid4vc/pull/65))
- add `Extension` trait for `SIOPv2` and `OID4VP` ([#60](https://github.com/impierce/openid4vc/pull/60))
- ExternalSign, optional endpoints, VpToken ([#55](https://github.com/impierce/openid4vc/pull/55))
- add credential_offer_uri ([#52](https://github.com/impierce/openid4vc/pull/52))
- add Batch Credential Endpoint ([#51](https://github.com/impierce/openid4vc/pull/51))
- add pre-authorized code flow ([#44](https://github.com/impierce/openid4vc/pull/44))
- initial VP support ([#21](https://github.com/impierce/openid4vc/pull/21))

### Documentation

- add introductory documentation for all crates ([#57](https://github.com/impierce/openid4vc/pull/57))

### Fixed

- *(oid4vc-manager)* resolve P-256 keys in `KeyValidator` ([#177](https://github.com/impierce/openid4vc/pull/177))
- [**breaking**] fix various parser bugs and panics ([#163](https://github.com/impierce/openid4vc/pull/163))
- make `authorization_details` optional in (Pushed) Authorization Request ([#128](https://github.com/impierce/openid4vc/pull/128))
- improve deserialization robustness and simplify generics ([#114](https://github.com/impierce/openid4vc/pull/114))
- deprecate async-trait for the Sign trait ([#49](https://github.com/impierce/openid4vc/pull/49))

### Other

- *(oid4vp)* [**breaking**] build presentation JWTs with IdentityKit ([#174](https://github.com/impierce/openid4vc/pull/174))
- *(oid4vp)* [**breaking**] validate VP tokens with IdentityKit ([#173](https://github.com/impierce/openid4vc/pull/173))
- [**breaking**] replace `did-key` with IdentityKit's `did:key` ([#172](https://github.com/impierce/openid4vc/pull/172))
- [**breaking**] replace `derivative`, `paste` and `lazy_static` ([#171](https://github.com/impierce/openid4vc/pull/171))
- [**breaking**] replace `did_url` with IdentityKit's `Did` ([#170](https://github.com/impierce/openid4vc/pull/170))
- *(deps)* [**breaking**] update all dependencies to latest versions ([#164](https://github.com/impierce/openid4vc/pull/164))
- reference workspace license ([#117](https://github.com/impierce/openid4vc/pull/117))
- bump `identity_credential` to `v1.6.0-beta.7` ([#110](https://github.com/impierce/openid4vc/pull/110))
- pin identity dependencies to v1.6.0-beta.2 ([#103](https://github.com/impierce/openid4vc/pull/103))
- support multiple did's and oid4vc-manager ([#28](https://github.com/impierce/openid4vc/pull/28))
