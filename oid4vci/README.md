# OpenID for Verifiable Credential Issuance
This is a Rust library for the OpenID for Verifiable Credential Issuance (OpenID4VCI) specification developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.net/wg/digital-credentials-protocols/).

| Specification      | Description                                | Version
| -------------------| ------------------------------------------ | -------
| [OID4VCI](oid4vci) | OpenID for Verifiable Credential Issuance  | [Working Group Draft 13 published: 8 February 2024](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html)

An overview of all the OpenID Digital Credentials Protocols implementation in Rust can be found [here](../README.md).

## Description
The OpenID for Verifiable Credential Issuance specification outlines an API that serves the purpose of issuing Verifiable Credentials. It is designed to support a range of formats, including W3C formats as well as other Credential formats like ISO.18013-5.

Verifiable Credentials bear a strong resemblance to identity assertions, akin to ID Tokens in OpenID Connect. They enable a Credential Issuer to assert claims on behalf of an End-User. These Verifiable Credentials adhere to a predefined schema, known as the Credential type, and they may be associated with a specific holder, often through cryptographic holder binding. Importantly, Verifiable Credentials can be securely presented to the RP (Relying Party) without requiring the direct involvement of the Credential Issuer.

Access to this API is granted through the authorization mechanism provided by OAuth 2.0. In essence, the Wallet employs
OAuth 2.0 to obtain the necessary authorization for receiving Verifiable Credentials. This approach leverages the
well-established security, simplicity, and flexibility of OAuth 2.0. It also allows existing OAuth 2.0 deployments and
OpenID Connect OPs to extend their functionality to become Credential Issuers.

# OpenID4VCI Implementation Checklist 📋
This table tracks our implementation progress toward full OpenID for Verifiable Credential Issuance (OpenID4VCI) compliance. 
This specification list is based off draft 13 of the OpenID4VCI document, though important additions from the latest specifications have also been added. 

| Spec. Reference | Feature | Implemented |
|---------------|---------|:-------------:|
| 📖 | Support for Pre-Authorized Code Flow | ✅ |
|  | Support for Authorization Code Flow | ❌ |
|  | Implementation of Authorization Server role (if separate from Issuer) | ❌ |
|  | Support for multiple Credential formats | ❌ |
| 3.1 | Metadata endpoint implementation (/.well-known/openid-credential-issuer) | ✅ |
| 3.1.1 | Support for `credential_issuer` field | ✅ |
| 3.1.1 | Support for `credential_endpoint` field | ✅ |
| 3.1.1 | Support for `batch_credential_endpoint` field† | ✅ |
| 3.1.1 | Support for `deferred_credential_endpoint` field | ❌ |
| 3.1.1 | Support for `notification_endpoints_supported` field | ❌ |
| 3.1.1 | Support for `credential_configurations_supported` array | ✅ |
| 3.1.1 | Support for `credential_identifiers_supported` field | ❌ |
| 3.1.1 | Support for `authorization_servers` array | ❌ |
| 3.1.1 | Support for `display` object (for issuer display) | ❌ |
| 3.1.1 | Support for `grant_types_supported` array | ✅ |
| 3.1.1 | Support for `token_endpoint` field | ✅ |
| 4 | **Credential Offer Endpoint** | ❌ |
| 4.1 | Support for Credential Offer object | ✅ |
| 4.1.1 | Support for `credential_issuer` field in offer | ✅ |
| 4.1.1 | Support for `credential_configuration_ids` field in offer | ✅ |
| 4.1.1 | Support for `grants` object in offer | ✅ |
| 4.1.1 | Support for `pre-authorized_code` grant type | ✅ |
| 4.1.1 | Support for `authorization_code` grant type | ✅ |
| 4.1.1 | Support for `tx_code` parameter | ❌ |
| 4.1.2 | Support for sending Credential Offer by Value using `credential_offer` Parameter | ✅ |
| 4.1.3 | Support for sending Credential Offer by Reference using `credential_offer_uri` | ✅ |
| 4.2 | Credential Offer Response | ✅ |
| 4.3 | Support for deep linking with `openid-credential-offer://` scheme | ✅ |
| 4.4 | Support for QR code presentation of offers | ✅ |
| 5 | **Authorization Endpoint** | ✅ |
| 5.1.1 | Authorization Request using `authorization_details` parameter | ❌ |
| 5.1.2 | Authorization Request using `scope` parameter | ❌ |
| 5.1.3 | Request Parameter: wallet_issuer | ❌ |
| 5.1.3 | Request Parameter: user_hint | ❌ |
| 5.1.3 | Request Parameter: issuer_state | ❌ |
| 5.1.1 | Support for Authorization Code Grant | ❌ |
| 5.1.1 | Support for PKCE | ❌ |
| 5.1.2 | Support for Pre-Authorized Code Grant | ✅ |
| 5.1.3 | Support for Refresh Token Grant | ❌ |
| 5.2 | Support for Transaction Codes | ❌ |
| 5.3 | Support for accessing OAuth endpoints with Authorization Code Grant | ✅ |
| 5.1.4 | Support for Pushed Authorization Request | ✅ |
| 5.1.5 | Support for Dynamic Credential Request | ✅ |
| 5.2 | Successful Authorization Response | ✅ |
| 5.3 | Authorization Error Response | ❌ |
| 6 | **Token Endpoint** | ✅ |
| 6.1 | Support for Token Requests | ✅ |
| 6.1 | Use of `pre-authorized_code` in Token Requests | ✅ |
| 6.1 | Use of `tx_code` in Token Requests | ❌ |
| 6.2 | Successful Token Response | ✅ |
| 6.3 | Token Error Response | ❌ |
| 7 | **Credential Endpoint** | ✅ |
| 7.2 | Support for credential request with `format` parameter | ✅ |
| 7.2 | Support for credential request with `credential_identifier` parameter | ❌ |
| 7.2 | Support for `proof` parameter in credential request | ✅ |
| 7.2 | Support for `proofs` parameter in credential request | ❌ |
| 7.2 | Support for `credential_response_encryption` parameter | ❌ |
| 7.2 | Support for JWT-secured credential requests | ✅ |
| 7.2.1.1 | Proof type: jwt | ✅ |
| 7.2.1.1 | Proof type: cwt† | ❌ |
| 7.2.1.2 | Proof type: ldp_vp | ❌ |
| 7.2.1.3 | Proof type: attestation* | ❌ |
| 7.2.2 | Proof verification support | ❌ |
| 7.2.2 | Support for proof nonce generation and validation | ❌ |
| 7.3 | Support for Credential Response | ✅ |
| 7.3 | `credentials` parameter in Credential Response Body | ✅ |
| 7.3 | `transaction_id` in Credential Reponse Body | ✅ |
| 7.3 | `notification_id` in Credential Response Body | ✅ |
| 7.3 | `c_nonce` parameter in Credential Response Body | ✅ |
| 7.3 | `c_nonce_expires_in` Credential Response Body | ✅ |
| 7.3.1.1 | Support for Credential Authorization Errors | ❌ |
| 7.3.1.2 | Support for Credential Request Errors | ❌ |
| 7.3.1.2 | `invalid_credential_request` Error Parameter | ❌ |
| 7.3.1.2 | `unsupported_credential_type` Error Parameter | ❌ |
| 7.3.1.2 | `invalid_proof` Error Parameter | ❌ |
| 7.3.1.2 | `invalid_nonce` Error Parameter | ❌ |
| 7.3.1.2 | `invalid_encryption_parameters` Error Parameter | ❌ |
| 7.3.1.2 | `credential_request_denied` Error Parameter | ❌ |
| 7.3.1.2 | Support for `error_description` parameter | ❌ |
| 7.3.2 | Credential Issuer provided Nonce (`invalid_proof` error code) |  |
| **Draft 15 Additions** |  |  |
| **7** | **Nonce Endpoint*** | ❌ |
| **7.1** | **Nonce Request using HTTP Post** | ❌ |
| **7.1** | **Nonce Response** (incl. `c_nonce`) | ❌ |
| 8 | **Batch Credential Endpoint†** | ✅ |
| 8.1 | Batch Credential Request using `credential_request` parameter | ❌ |
| 8.2 | Batch Credential Response using `credential_responses` parameter | ✅ |
| 8.2 | Batch Credential Response using `c_nonce` parameter | ✅ |
| 8.2 | Batch Credential Response using `c_nonce_expires_in` parameter | ✅ |
| 8.3 | Batch Credential Error Response - Bad Request status code | ❌ |
| 9 | **Deferred Credential Endpoint** | ❌ |
| 9.1 | Support for Deferred Credential Requests | ❌ |
| 9.2 | Support for Deferred Credential Responses | ❌ |
| 9.3 | Deferred Credential Error Responses | ❌ |
| 9.3 | Additional `issuance_pending` parameter | ❌ |
| 9.3 | Additional `invalid_transaction_id` parameter | ❌ |
| 10 | **Notification Endpoint support** | ✅ |
| 10.1 | Support for Notification Requests | ✅ |
| 10.1 | Support for `notification_id` Parameter | ✅ |
| 10.1 | Support for event parameter (credential_accepted/failure/deleted) | ✅ |
| 10.2 | Successful Notification Response | ✅ |
| 10.3 | Notification Error Reponse with `invalid_notifcation_id` parameter | ❌ |
| 10.3 | Notification Error Reponse with `invalid_notifcation_request` parameter | ❌ |
| 11 | **Metadata** | ❌ |
| 11.1 | credential_offer_endpoint (for Wallets) | ❌ |
| 11.2.2 | usage of /.well-known/openid-credential-issuer for Credential Issuers | ✅ |
| 11.2.3 | credential_issuer parameter | ✅ |
| 11.2.3 | authorization_servers parameter | ✅ |
| 11.2.3 | credential_endpoint parameter | ✅ |
| 11.2.3 | batch_credential_endpoint parameter | ✅ |
| 11.2.3 | deferred_credential_endpoint parameter | ✅ |
| 11.2.3 | notification_endpoint parameter | ✅ |
| 11.2.3 | credential_response_encryption parameter | ❌ |
| 11.2.3 | credential_identifiers_supported parameter | ❌ |
| 11.2.3 | signed_metadata parameter | ❌ |
| 11.2.3 | display parameters | ✅ |
| 11.2.3 | credential_configurations_supported: `parameter` | ✅ |
| 11.2.3 | credential_configurations_supported: `format` | ✅ |
| 11.2.3 | credential_configurations_supported: `scope` | ✅ |
| 11.2.3 | credential_configurations_supported: `cryptographic_binding_methods_supported` | ✅ |
| 11.2.3 | credential_configurations_supported: `credential_signing_alg_values_supported` | ✅ |
| 11.2.3 | credential_configurations_supported: `proof_types_supported` | ✅ |
| 11.3 | `pre-authorized_grant_anonymous_access_supported` parameter | ❌ |

*Addition in Draft 15* | Deprecated in Draft 15†*