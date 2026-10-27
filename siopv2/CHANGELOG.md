# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/impierce/openid4vc/compare/siopv2-v0.2.0...siopv2-v0.3.0) - 2026-10-27

### Dependencies

- *(deps)* [**breaking**] update `oid4vc-core` to 0.3.0, which uses identity-kit 0.3.0 ([#190](https://github.com/impierce/openid4vc/pull/190))

## [0.2.0](https://github.com/impierce/openid4vc/compare/siopv2-v0.1.0...siopv2-v0.2.0) - 2026-10-25

### Added

- expose protocol schemas with `utoipa` ([#136](https://github.com/impierce/openid4vc/pull/136))
- *(tracing)* add structured tracing instrumentation across workspace ([#134](https://github.com/impierce/openid4vc/pull/134))
- implement Interactive Authorization flow ([#127](https://github.com/impierce/openid4vc/pull/127))
- enhance `VpToken` validation ([#121](https://github.com/impierce/openid4vc/pull/121))
- update OpenID4VCI to Draft 15, support Authorization Code flow ([#106](https://github.com/impierce/openid4vc/pull/106))
- update `oid4vp` to draft 28 ([#98](https://github.com/impierce/openid4vc/pull/98))
- require `Debug` supertrait for `ExternalSign` and `Subject` ([#97](https://github.com/impierce/openid4vc/pull/97))
- add support for multiple signing algorithms ([#76](https://github.com/impierce/openid4vc/pull/76))
- make trait methods in `oid4vc-core` async ([#74](https://github.com/impierce/openid4vc/pull/74))
- add support for using multiple DID methods ([#70](https://github.com/impierce/openid4vc/pull/70))
- update SIOPv2 to WG Draft 13 ([#61](https://github.com/impierce/openid4vc/pull/61))
- update OpenID4VP to WG Draft 20 ([#62](https://github.com/impierce/openid4vc/pull/62))
- add `Clone`, `Default`, `PartialEq` implementations to several types ([#65](https://github.com/impierce/openid4vc/pull/65))
- add `Extension` trait for `SIOPv2` and `OID4VP` ([#60](https://github.com/impierce/openid4vc/pull/60))
- ExternalSign, optional endpoints, VpToken ([#55](https://github.com/impierce/openid4vc/pull/55))
- add Batch Credential Endpoint ([#51](https://github.com/impierce/openid4vc/pull/51))
- add pre-authorized code flow ([#44](https://github.com/impierce/openid4vc/pull/44))
- initial VP support ([#21](https://github.com/impierce/openid4vc/pull/21))
- improved builder pattern for RequestUrl ([#27](https://github.com/impierce/openid4vc/pull/27))
- add monorepo ([#29](https://github.com/impierce/openid4vc/pull/29))

### Documentation

- add introductory documentation for all crates ([#57](https://github.com/impierce/openid4vc/pull/57))

### Fixed

- [**breaking**] fix various parser bugs and panics ([#163](https://github.com/impierce/openid4vc/pull/163))
- use preferred `supported_subject_syntax_type` by default ([#108](https://github.com/impierce/openid4vc/pull/108))
- change request objects `typ` to `oauth-authz-req+jwt` ([#83](https://github.com/impierce/openid4vc/pull/83))
- deprecate async-trait for the Sign trait ([#49](https://github.com/impierce/openid4vc/pull/49))
- fix serde for id_token vp_token
- fix keyword

### Other

- [**breaking**] replace `derivative`, `paste` and `lazy_static` ([#171](https://github.com/impierce/openid4vc/pull/171))
- [**breaking**] replace `did_url` with IdentityKit's `Did` ([#170](https://github.com/impierce/openid4vc/pull/170))
- *(deps)* [**breaking**] update all dependencies to latest versions ([#164](https://github.com/impierce/openid4vc/pull/164))
- support multiple did's and oid4vc-manager ([#28](https://github.com/impierce/openid4vc/pull/28))
