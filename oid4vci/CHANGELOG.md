# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/impierce/openid4vc/compare/oid4vci-v0.1.0...oid4vci-v0.2.0) - 2026-10-25

### Added

- expose protocol schemas with `utoipa` ([#136](https://github.com/impierce/openid4vc/pull/136))
- *(tracing)* add structured tracing instrumentation across workspace ([#134](https://github.com/impierce/openid4vc/pull/134))
- introduce `utoipa` feature, document `TxCodeConstraints` schema ([#132](https://github.com/impierce/openid4vc/pull/132))
- implement Interactive Authorization flow ([#127](https://github.com/impierce/openid4vc/pull/127))
- update Credential Format extension point for `vc+sd-jwt` ([#118](https://github.com/impierce/openid4vc/pull/118))
- migrate OID4VCI and OID4VP to 1.0  ([#119](https://github.com/impierce/openid4vc/pull/119))
- update OpenID4VCI to Draft 15, support Authorization Code flow ([#106](https://github.com/impierce/openid4vc/pull/106))
- add TxCode to Credential Offer parameters ([#107](https://github.com/impierce/openid4vc/pull/107))
- update `oid4vp` to draft 28 ([#98](https://github.com/impierce/openid4vc/pull/98))
- feat : implement Display and Error traits for OID4VCI error types ([#92](https://github.com/impierce/openid4vc/pull/92))
- require `Debug` supertrait for `ExternalSign` and `Subject` ([#97](https://github.com/impierce/openid4vc/pull/97))
- implement error responses ([#90](https://github.com/impierce/openid4vc/pull/90))
- add `NotificationRequest` struct
- bootstrap SD-JWT support ([#82](https://github.com/impierce/openid4vc/pull/82))
- derive `Clone` trait for `TokenRequest` ([#79](https://github.com/impierce/openid4vc/pull/79))
- add support for multiple signing algorithms ([#76](https://github.com/impierce/openid4vc/pull/76))
- make trait methods in `oid4vc-core` async ([#74](https://github.com/impierce/openid4vc/pull/74))
- add support for using multiple DID methods ([#70](https://github.com/impierce/openid4vc/pull/70))
- update OpenID4VCI to WG Draft 13 ([#64](https://github.com/impierce/openid4vc/pull/64))
- update SIOPv2 to WG Draft 13 ([#61](https://github.com/impierce/openid4vc/pull/61))
- add `Clone`, `Default`, `PartialEq` implementations to several types ([#65](https://github.com/impierce/openid4vc/pull/65))
- add `Extension` trait for `SIOPv2` and `OID4VP` ([#60](https://github.com/impierce/openid4vc/pull/60))
- ExternalSign, optional endpoints, VpToken ([#55](https://github.com/impierce/openid4vc/pull/55))
- add credential_offer_uri ([#52](https://github.com/impierce/openid4vc/pull/52))
- add Batch Credential Endpoint ([#51](https://github.com/impierce/openid4vc/pull/51))
- add pre-authorized code flow ([#44](https://github.com/impierce/openid4vc/pull/44))
- initial VP support ([#21](https://github.com/impierce/openid4vc/pull/21))
- add monorepo ([#29](https://github.com/impierce/openid4vc/pull/29))

### Documentation

- add `AuthorizationRequest` comments ([#129](https://github.com/impierce/openid4vc/pull/129))
- Update OID4VC Checklist for readability ([#94](https://github.com/impierce/openid4vc/pull/94))
- add implementation checklist for OpenID4VCI specifications ([#89](https://github.com/impierce/openid4vc/pull/89))
- add introductory documentation for all crates ([#57](https://github.com/impierce/openid4vc/pull/57))

### Fixed

- [**breaking**] fix various parser bugs and panics ([#163](https://github.com/impierce/openid4vc/pull/163))
- make `authorization_details` optional in (Pushed) Authorization Request ([#128](https://github.com/impierce/openid4vc/pull/128))
- validate all Credentials and nonces in Authorization Response ([#115](https://github.com/impierce/openid4vc/pull/115))
- improve deserialization robustness and simplify generics ([#114](https://github.com/impierce/openid4vc/pull/114))
- update OAuth Authorization Server Metadata endpoint construction ([#113](https://github.com/impierce/openid4vc/pull/113))
- change proof signing algorithms type from `Algorithm` to `String` ([#112](https://github.com/impierce/openid4vc/pull/112))
- evaluate `meta` in DCQL query, handle error gracefully ([#109](https://github.com/impierce/openid4vc/pull/109))
- remove extra quotation marks from credential offer URIs ([#100](https://github.com/impierce/openid4vc/pull/100))
- pop trailing slash when requesting Issuer metadata ([#91](https://github.com/impierce/openid4vc/pull/91))
- make `proof_types_supported` requirement optional ([#84](https://github.com/impierce/openid4vc/pull/84))
- fix keyword

### Other

- [**breaking**] replace `derivative`, `paste` and `lazy_static` ([#171](https://github.com/impierce/openid4vc/pull/171))
- *(deps)* [**breaking**] update all dependencies to latest versions ([#164](https://github.com/impierce/openid4vc/pull/164))
- pin identity dependencies to v1.6.0-beta.2 ([#103](https://github.com/impierce/openid4vc/pull/103))
- support multiple did's and oid4vc-manager ([#28](https://github.com/impierce/openid4vc/pull/28))
