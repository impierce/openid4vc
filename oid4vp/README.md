# OpenID for Verifiable Presentations
This is a Rust library for the OpenID for Verifiable Presentations (OpenID4VP) specification developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.net/wg/digital-credentials-protocols/).

| Specification      | Description                                | Version
| -------------------| ------------------------------------------ | -------
| [OID4VP](oid4vp)   | OpenID for Verifiable Presentations        | [Editor's Draft published: 30 August 2023](https://github.com/openid/OpenID4VP/blob/965597ae01fc6e6a2bddc0d6b16f3f6122f3c1ab/openid-4-verifiable-presentations-1_0.md)


An overview of all the OpenID Digital Credentials Protocols implementation in Rust can be found [here](../README.md).

## Description
The OpenID for Verifiable Presentations specification establishes a protocol that builds upon OAuth 2.0. Its primary purpose is to facilitate the presentation of Verifiable Credentials in the form of Verifiable Presentations. These Verifiable Credentials and Presentations can take various formats, including but not limited to the W3C Verifiable Credentials Data Model, ISO mdoc, and AnonCreds.

The choice of OAuth 2.0 as the foundational protocol is strategic, as it provides the essential framework necessary to construct a straightforward, secure, and user-friendly layer for presenting Credentials. This layer is built atop OAuth 2.0, leveraging its existing mechanisms. Importantly, this specification enables implementers to seamlessly support the presentation of Credentials and the issuance of Access Tokens. These Access Tokens are crucial for gaining access to APIs based on Verifiable Credentials stored in a Wallet.

Furthermore, this specification serves the purpose of extending OpenID Connect deployments. By doing so, it empowers these deployments with the capability to transport Verifiable Presentations. The inclusion of Verifiable Presentations enhances the capabilities of OpenID Connect deployments and broadens the scope of their applications.

It's worth noting that this specification can also be used in conjunction with [SIOPv2](../siopv2) when implementers require OpenID Connect functionalities, such as the issuance of Self-Issued ID Tokens. This flexibility allows for the integration of OpenID Connect features into the Verifiable Credentials ecosystem.
