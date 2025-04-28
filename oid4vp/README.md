# OpenID for Verifiable Presentations

This is a Rust library for the OpenID for Verifiable Presentations (OpenID4VP) specification developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.net/wg/digital-credentials-protocols/).

| Specification    | Description                         | Version                                                                                                                      |
| ---------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [OID4VP](oid4vp) | OpenID for Verifiable Presentations | [Working Group Draft 20 published: 29 November 2023](https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html) |

An overview of all the OpenID Digital Credentials Protocols implementation in Rust can be found [here](../README.md).

## Description

The OpenID for Verifiable Presentations specification establishes a protocol that builds upon OAuth 2.0. Its primary purpose is to facilitate the presentation of Verifiable Credentials in the form of Verifiable Presentations. These Verifiable Credentials and Presentations can take various formats, including but not limited to the W3C Verifiable Credentials Data Model, ISO mdoc, and AnonCreds.

The choice of OAuth 2.0 as the foundational protocol is strategic, as it provides the essential framework necessary to construct a straightforward, secure, and user-friendly layer for presenting Credentials. This layer is built atop OAuth 2.0, leveraging its existing mechanisms. Importantly, this specification enables implementers to seamlessly support the presentation of Credentials and the issuance of Access Tokens. These Access Tokens are crucial for gaining access to APIs based on Verifiable Credentials stored in a Wallet.

Furthermore, this specification serves the purpose of extending OpenID Connect deployments. By doing so, it empowers these deployments with the capability to transport Verifiable Presentations. The inclusion of Verifiable Presentations enhances the capabilities of OpenID Connect deployments and broadens the scope of their applications.

It's worth noting that this specification can also be used in conjunction with [SIOPv2](../siopv2) when implementers require OpenID Connect functionalities, such as the issuance of Self-Issued ID Tokens. This flexibility allows for the integration of OpenID Connect features into the Verifiable Credentials ecosystem.

# OpenID4VP Implementation Checklist 📋

This table tracks implementation progress toward full OpenID for Verifiable Presentations (OpenID4VP) compliance and references [Draft 20](https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html) in adjacent to [Draft 23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#name-introduction)

**Legend:**

- **★** New in draft 23
- **†** Removed since draft 20

| Spec. Reference       | Feature                                                                        | Implemented |
| --------------------- | ------------------------------------------------------------------------------ | :---------: |
| 📖                    | Support for Same Device Flow                                                   |     ❌      |
|                       | Support for Cross Device Flow                                                  |     ✅      |
|                       | Support for Response Type `vp_token`                                           |     ✅      |
|                       | Support for Response Type `vp_token id_token`                                  |     ✅      |
|                       | Support for DCQL (Digital Credentials Query Language) **★**                    |     ❌      |
|                       | Support for Presentation Exchange                                              |     ✅      |
| **5**                 | **Authorization Request**                                                      |             |
| 5.1                   | Support for `presentation_definition` parameter                                |     ✅      |
| 5.1                   | Support for `presentation_definition_uri` parameter                            |     ❌      |
| 5.1                   | Support for `client_metadata_uri` parameter **†**                              |     ✅      |
| 5.1                   | Support for `dcql_query` parameter **★**                                       |     ❌      |
| 5.1                   | Support for `client_metadata` parameter                                        |     ✅      |
| 5.1                   | Support for `request_uri_method` parameter **★**                               |     ❌      |
| 5.1                   | Support for `transaction_data` parameter **★**                                 |     ❌      |
| 5.2                   | Support for required `nonce` parameter                                         |     ✅      |
| 5.2                   | Support for `scope` parameter for requesting VCs                               |     ✅      |
| 5.2                   | Support for `response_mode` parameter                                          |     ✅      |
| 5.2                   | Support for `client_id` parameter with Client Identifier Schemes               |     ✅      |
| 5.4                   | Ability to process Presentation Definition JSON object                         |     ✅      |
| 5.5                   | Ability to retrieve Presentation Definition via URI                            |     ❌      |
| 5.6                   | Support for requesting VCs using `scope` values                                |     ✅      |
| 5.7                   | Support for Response Type `vp_token`                                           |     ✅      |
| 5.8                   | Support for passing Authorization Request across devices (QR code)             |     ✅      |
| 5.9                   | Handling `aud` claim in Request Objects                                        |     ✅      |
| 5.10                  | Support for Client Identifier Schemes                                          |     ✅      |
| 5.10.4                | Support for `redirect_uri` Client Identifier Scheme                            |     ✅      |
| 5.10.4                | Support for `https` Client Identifier Scheme **★**                             |     ❌      |
| 5.10.4                | Support for `did` Client Identifier Scheme                                     |     ✅      |
| 5.10.4                | Support for `verifier_attestation` Client Identifier Scheme                    |     ✅      |
| 5.10.4                | Support for `x509_san_dns` Client Identifier Scheme                            |     ✅      |
| 5.10.4                | Support for `x509_san_uri` Client Identifier Scheme                            |     ✅      |
| 5.10.4                | Support for `entity_id` Client Identifier Scheme **†**                         |     ❌      |
| 5.10.4                | Support for `pre-registered` Client Identifier Scheme **†**                    |     ❌      |
| 5.10.4                | Support for `web-origin` Client Identifier Scheme **★**                        |     ❌      |
| 5.11                  | Support for Request URI Method: `post` **★**                                   |     ❌      |
| 5.11                  | Processing `wallet_metadata` parameter when Request URI POST **★**             |     ❌      |
| 5.11                  | Processing `wallet_nonce` parameter in Request URI POST **★**                  |     ❌      |
| **6**                 | **Digital Credentials Query Language (DCQL)** **★**                            |             |
| 6.1                   | Support for Credential Query **★**                                             |     ❌      |
| 6.2                   | Support for Credential Set Query **★**                                         |     ❌      |
| 6.3                   | Support for Claims Query **★**                                                 |     ❌      |
| 6.3.1                 | Implementing rules for selecting claims and credentials **★**                  |     ❌      |
| 6.4                   | Support for Claims Path Pointer **★**                                          |     ❌      |
| 6.4.1                 | Processing Claims Path Pointer arrays **★**                                    |     ❌      |
| **7**                 | **Response**                                                                   |             |
| 7.1                   | Support for `vp_token` response parameter                                      |     ✅      |
| 7.1                   | Support for `presentation_submission` response parameter                       |     ✅      |
| 7.2                   | Support for Response Mode `direct_post`                                        |     ✅      |
| 7.2                   | Handling of `response_uri` parameter                                           |     ❌      |
| 7.3                   | Support for signed and/or encrypted responses using JARM                       |     ❌      |
| 7.3.1                 | Support for Response Mode `direct_post.jwt`                                    |     ❌      |
| 7.4                   | Support for transaction data mechanism **★**                                   |     ❌      |
| 7.5                   | Error response handling (invalid_scope, invalid_request, invalid_client, etc.) |     ❌      |
| 7.6                   | Implementation of VP Token validation                                          |     ❌      |
| **8**                 | **Wallet Invocation**                                                          |             |
| 8                     | Support for custom URL scheme (e.g., `openid4vp://`)                           |     ✅      |
| 8                     | Support for domain-bound Universal Links/App link                              |     ❌      |
| 8                     | Support for QR code scanning                                                   |     ✅      |
| **9**                 | **Wallet Metadata (Authorization Server Metadata)**                            |             |
| 9.1                   | Support for `presentation_definition_uri_supported` metadata parameter         |     ❌      |
| 9.1                   | Support for `vp_formats_supported` metadata parameter                          |     ❌      |
| 9.1                   | Support for `client_id_schemes_supported` metadata parameter                   |     ❌      |
| 9.2                   | Support for dynamic discovery of Wallet's metadata                             |     ❌      |
| **10**                | **Verifier Metadata (Client Metadata)**                                        |             |
| 10.1                  | Support for `vp_formats` metadata parameter                                    |     ✅      |
| **11**                | **Verifier Attestation JWT**                                                   |             |
| 11                    | Handling Verifier Attestation JWT with proper claims                           |     ❌      |
| 11                    | Validating `cnf` claim in Verifier Attestation JWT                             |     ❌      |
| 11                    | Using `jwt` JOSE header for Verifier Attestation JWT                           |     ❌      |
| **12**                | **Implementation Considerations**                                              |             |
| 12.1                  | Support for static configuration values                                        |     ✅      |
| 12.1.2                | Support for `openid4vp://` scheme with static configuration values             |     ❌      |
| 12.3                  | Support for state management                                                   |     ✅      |
| 12.4                  | Implementation of Response Mode `direct_post` with security considerations     |     ✅      |
| **Appendix A**        | **OpenID4VP over the Digital Credentials API** **★**                           |             |
| A.1                   | Support for `openid4vp` protocol value in DC API **★**                         |     ❌      |
| A.2                   | Support for sending request parameters via DC API **★**                        |     ❌      |
| A.3                   | Support for both signed and unsigned requests via DC API **★**                 |     ❌      |
| A.3.1                 | Support for unsigned requests in DC API **★**                                  |     ❌      |
| A.3.2                 | Support for signed requests in DC API **★**                                    |     ❌      |
| A.4                   | Providing responses through DC API **★**                                       |     ❌      |
| **Appendix B**        | **Credential Format Specific Parameters**                                      |     ❌      |
| B.1                   | Support for W3C Verifiable Credentials                                         |     ✅      |
| B.1.1                 | Support for VC signed as JWT, not using JSON-LD                                |     ✅      |
| B.1.2                 | Support for LDP VCs                                                            |     ✅      |
| B.2                   | Support for AnonCreds                                                          |     ✅      |
| B.3                   | Support for ISO mdoc                                                           |     ✅      |
| B.4                   | Support for IETF SD-JWT VC                                                     |     ⚠️      |
| B.5                   | Support for combining with SIOPv2                                              |     ✅      |
|                       |                                                                                |             |
| **Security Features** | Below are suggested security implementations:                                  |             |
| 13.1                  | Implementation of VP Token replay prevention                                   |     ❌      |
| 13.2                  | Protection against session fixation attacks                                    |     ❌      |
| 13.3                  | Security measures for Response Mode `direct_post`                              |     ❌      |
| 13.5                  | Secure handling of encrypted unsigned responses (see 13.1)                     |     ❌      |
| 13.6                  | DIF Presentation Exchange security considerations                              |     ❌      |
| 13.7                  | Implementation of TLS requirements                                             |     ❌      |
