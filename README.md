# Rust library for OpenID for Verifiable Credentials

[![codecov](https://codecov.io/github/impierce/openid4vc/graph/badge.svg?token=CDL92C53JL)](https://codecov.io/github/impierce/openid4vc)

This is a library for the OpenID for Verifiable Credentials (OpenID4VC) specifications family developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.net/wg/digital-credentials-protocols/).

The Digital Credentials Protocols (DCP) Working Group focuses on creating OpenID specifications for a model where
issuers provide digital credentials to holders, allowing holders to present them to verifiers. These digital
credentials contain cryptographically signed statements about the holder, and verifiers can check their authenticity.
The primary goals include enhancing user control and privacy over identity information, making identity verification
more efficient and secure, and establishing a universal approach for identification, authentication, and authorization
in both digital and physical spaces.

An overview of all the specifications developed by the OpenID Digital Credentials Protocols Working Group can be found [here](https://openid.net/wg/digital-credentials-protocols/specifications/).

This workspace includes Rust implementations for the following DCP specifications:
| Specification | Description | Version
| -------------------| ------------------------------------------ | -------
| [OID4VCI](oid4vci) | OpenID for Verifiable Credential Issuance 1.0 | [OID4VCI 1.0 published: 16 September 2025](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#)
| [OID4VP](oid4vp) | OpenID for Verifiable Presentations | [Working Group Draft 28 published: 24 April 2025](https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html)
| [SIOPv2](siopv2) | Self-Issued OpenID Provider v2 | [Working Group Draft 13 published: 28 November 2023](https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html)

### OID4VC Manager

For an easy-to-use library that combines all the above specifications, please check out:

- [OID4VC-Manager](oid4vc-manager)
