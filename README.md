# Rust library for OpenID for Verifiable Credentials

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
* [OID4VCI](oid4vci): OpenID for Verifiable Credential Issuance
* [OID4VP](oid4vp): OpenID for Verifiable Presentations
* [SIOPv2](siopv2): Self-Issued OpenID Provider v2

On top of that, this workspace also includes a library for the [DIF Presentation Exchange
2.0.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/):
* [DIF Presentation Exchange](dif-presentation-exchange)

For an easy-to-use library that combines all the above specifications, please check out:
* [OID4VC-Manager](oid4vc-manager)
