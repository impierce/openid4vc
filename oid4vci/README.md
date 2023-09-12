# OpenID for Verifiable Credential Issuance
This is a Rust library for the [OpenID for Verifiable Credential Issuance](https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html) (OpenID4VCI) specification developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html).

An overview of all the OpenID Digital Credentials Protocols implementation in Rust can be found [here](../README.md).

## Description
The OpenID for Verifiable Credential Issuance specification outlines an API that serves the purpose of issuing Verifiable Credentials. It is designed to support a range of formats, including W3C formats as well as other Credential formats like ISO.18013-5.

Verifiable Credentials bear a strong resemblance to identity assertions, akin to ID Tokens in OpenID Connect. They enable a Credential Issuer to assert claims on behalf of an End-User. These Verifiable Credentials adhere to a predefined schema, known as the Credential type, and they may be associated with a specific holder, often through cryptographic holder binding. Importantly, Verifiable Credentials can be securely presented to the RP (Relying Party) without requiring the direct involvement of the Credential Issuer.

Access to this API is granted through the authorization mechanism provided by OAuth 2.0. In essence, the Wallet employs
OAuth 2.0 to obtain the necessary authorization for receiving Verifiable Credentials. This approach leverages the
well-established security, simplicity, and flexibility of OAuth 2.0. It also allows existing OAuth 2.0 deployments and
OpenID Connect OPs to extend their functionality to become Credential Issuers.
