# OpenID for Verifiable Credential Issuance

This is a Rust library for the OpenID for Verifiable Credential Issuance (OpenID4VCI) specification developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.net/wg/digital-credentials-protocols/).

| Specification      | Description                               | Version                                                                                                                |
| ------------------ | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| [OID4VCI](oid4vci) | OpenID for Verifiable Credential Issuance | [OID4VCI 1.0 published: 16 September 2025](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#) |

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
This specification list is based off OpenID4VCI 1.0 document linked above.

**Legend:**

## General

| Spec Ref. | Feature                                                            | Implemented |
| --------- | ------------------------------------------------------------------ | :---------: |
|           | Support for Pre-Authorized Code Flow                               |     ✅      |
|           | Support for Authorization Code Flow                                |     ✅      |
|           | Implementation of Authorization Server role (separate from Issuer) |     ❌      |

## Credential Formats

| Spec Ref. | Feature                             | Implemented |
| --------- | ----------------------------------- | :---------: |
| A.1.1     | Support for `jwt_vc_json` format    |     ✅      |
| A.1.2     | Support for `ldp_vc` format         |     ❌      |
| A.1.3     | Support for `jwt_vc_json-ld` format |     ❌      |
| A.2       | Support for `mso_mdoc` format       |     ❌      |
| A.3       | Support for `dc+sd-jwt` format      |     ✅      |

## 4 — Credential Offer

| Spec Ref. | Feature                                                                        | Implemented |
| --------- | ------------------------------------------------------------------------------ | :---------: |
| 4.1       | Support for Credential Offer object                                            |     ✅      |
| 4.1.1     | `credential_issuer` field in offer                                             |     ✅      |
| 4.1.1     | `credential_configuration_ids` field in offer                                  |     ✅      |
| 4.1.1     | `grants` object in offer                                                       |     ✅      |
| 4.1.1     | Grant type `authorization_code` (incl. `issuer_state`, `authorization_server`) |     ✅      |
| 4.1.1     | Grant type `urn:ietf:params:oauth:grant-type:pre-authorized_code`              |     ✅      |
| 4.1.1     | `pre-authorized_code` parameter                                                |     ✅      |
| 4.1.1     | `tx_code` object (incl. `input_mode`, `length`, `description`)                 |     ✅      |
| 4.1.1     | `authorization_server` parameter in grant types                                |     ❌      |
| 4.1.2     | Sending Credential Offer by value (`credential_offer` parameter)               |     ✅      |
| 4.1.3     | Sending Credential Offer by reference (`credential_offer_uri` parameter)       |     ✅      |
|           | Deep linking with `openid-credential-offer://` scheme                          |     ✅      |
|           | QR code presentation of offers                                                 |     ✅      |

## 5 — Authorization Endpoint

| Spec Ref. | Feature                                                       | Implemented |
| --------- | ------------------------------------------------------------- | :---------: |
| 5.1.1     | Authorization Request using `authorization_details` parameter |     ✅      |
| 5.1.1     | `credential_configuration_id` in authorization details        |     ✅      |
| 5.1.1     | `claims` array in authorization details                       |     ✅      |
| 5.1.1     | `locations` field when multiple Authorization Servers         |     ❌      |
| 5.1.2     | Authorization Request using `scope` parameter                 |     ❌      |
| 5.1.2     | Use of `resource` parameter (RFC 8707)                        |     ❌      |
| 5.1.3     | `issuer_state` request parameter                              |     ✅      |
| 5.1.4     | Pushed Authorization Request (PAR) support                    |     ❌      |
|           | PKCE support (RFC 7636)                                       |     ✅      |
| 5.2       | Successful Authorization Response                             |     ✅      |
| 5.3       | Authorization Error Response                                  |     ✅      |

## 6 — Token Endpoint

| Spec Ref. | Feature                                                                 | Implemented |
| --------- | ----------------------------------------------------------------------- | :---------: |
| 6.1       | Token Request (Authorization Code Flow)                                 |     ✅      |
| 6.1       | Token Request (Pre-Authorized Code Flow)                                |     ✅      |
| 6.1       | `pre-authorized_code` parameter in Token Request                        |     ✅      |
| 6.1       | `tx_code` parameter in Token Request                                    |     ✅      |
| 6.1.1     | `authorization_details` parameter in Token Request                      |     ✅      |
| 6.2       | Successful Token Response                                               |     ✅      |
| 6.2       | `authorization_details` with `credential_identifiers` in Token Response |     ✅      |
| 6.3       | Token Error Response                                                    |     ✅      |
| 6.3       | Error: `invalid_request` (tx_code mismatch scenarios)                   |     ✅      |
| 6.3       | Error: `invalid_grant` (wrong tx_code / expired pre-auth code)          |     ✅      |
| 6.3       | Error: `invalid_client` (anonymous access not supported)                |     ✅      |

## 7 — Nonce Endpoint

| Spec Ref. | Feature                                    | Implemented |
| --------- | ------------------------------------------ | :---------: |
| 7         | Nonce Endpoint implementation              |     ✅      |
| 7.1       | Nonce Request (HTTP POST, no access token) |     ✅      |
| 7.2       | Nonce Response with `c_nonce` parameter    |     ✅      |
| 7.2       | `Cache-Control: no-store` on response      |     ✅      |

## 8 — Credential Endpoint

| Spec Ref. | Feature                                                   | Implemented |
| --------- | --------------------------------------------------------- | :---------: |
| 8         | Credential Endpoint implementation                        |     ✅      |
| 8.2       | `credential_identifier` parameter in request              |     ✅      |
| 8.2       | `credential_configuration_id` parameter in request        |     ✅      |
| 8.2       | `proofs` parameter in request (replaces singular `proof`) |     ✅      |
| 8.2       | `credential_response_encryption` parameter in request     |     ❌      |
| 8.3       | `credentials` array in response                           |     ✅      |
| 8.3       | `transaction_id` in response (deferred flow)              |     ❌      |
| 8.3       | `interval` in response (with `transaction_id`)            |     ❌      |
| 8.3       | `notification_id` in response                             |     ✅      |
| 8.3       | HTTP 200 for immediate issuance                           |     ✅      |
| 8.3       | HTTP 202 for deferred issuance                            |     ❌      |
| 8.3.1.1   | Authorization error responses (RFC 6750)                  |     ✅      |
| 8.3.1.2   | Error: `invalid_credential_request`                       |     ❌      |
| 8.3.1.2   | Error: `unknown_credential_configuration`                 |     ✅      |
| 8.3.1.2   | Error: `unknown_credential_identifier`                    |     ✅      |
| 8.3.1.2   | Error: `invalid_proof`                                    |     ✅      |
| 8.3.1.2   | Error: `invalid_nonce`                                    |     ✅      |
| 8.3.1.2   | Error: `invalid_encryption_parameters`                    |     ❌      |
| 8.3.1.2   | Error: `credential_request_denied`                        |     ❌      |
| 8.3.1.2   | `error_description` parameter                             |     ❌      |

## Proof Types (Appendix F)

| Spec Ref. | Feature                   | Implemented |
| --------- | ------------------------- | :---------: |
| F.1       | Proof type: `jwt`         |     ✅      |
| F.2       | Proof type: `di_vp`       |     ✅      |
| F.3       | Proof type: `attestation` |     ❌      |
| F.4       | Proof verification logic  |     ❌      |

## 9 — Deferred Credential Endpoint

| Spec Ref. | Feature                                                                       | Implemented |
| --------- | ----------------------------------------------------------------------------- | :---------: |
| 9         | Deferred Credential Endpoint implementation                                   |     ❌      |
| 9.1       | Deferred Credential Request (`transaction_id`)                                |     ❌      |
| 9.1       | `credential_response_encryption` in deferred request                          |     ❌      |
| 9.2       | Deferred Credential Response (HTTP 200 with `credentials`)                    |     ❌      |
| 9.2       | Deferred still-pending response (HTTP 202 with `transaction_id` + `interval`) |     ❌      |
| 9.2       | `notification_id` in deferred response                                        |     ❌      |
| 9.3       | Error: `invalid_transaction_id`                                               |     ❌      |
| 9.3       | Error: `credential_request_denied` (issuance no longer possible)              |     ❌      |

## 10 — Encrypted Credential Requests and Responses

| Spec Ref. | Feature                                             | Implemented |
| --------- | --------------------------------------------------- | :---------: |
| 10        | JWT-encoded encrypted requests (`application/jwt`)  |     ❌      |
| 10        | JWT-encoded encrypted responses (`application/jwt`) |     ❌      |
| 10        | Support for JWE `zip` compression                   |     ❌      |

## 11 — Notification Endpoint

| Spec Ref. | Feature                                                                | Implemented |
| --------- | ---------------------------------------------------------------------- | :---------: |
| 11        | Notification Endpoint implementation                                   |     ✅      |
| 11.1      | Notification Request (`notification_id`, `event`, `event_description`) |     ✅      |
| 11.1      | Event: `credential_accepted`                                           |     ✅      |
| 11.1      | Event: `credential_failure`                                            |     ✅      |
| 11.1      | Event: `credential_deleted`                                            |     ✅      |
| 11.2      | Successful Notification Response (HTTP 204)                            |     ✅      |
| 11.3      | Error: `invalid_notification_id`                                       |     ✅      |
| 11.3      | Error: `invalid_notification_request`                                  |     ✅      |

## 12 — Metadata

### 12.1 — Client (Wallet) Metadata

| Spec Ref. | Feature                                         | Implemented |
| --------- | ----------------------------------------------- | :---------: |
| 12.1      | `credential_offer_endpoint` client metadata     |     ❌      |
| 12.1.1    | Fallback to `openid-credential-offer://` scheme |     ✅      |

### 12.2 — Credential Issuer Metadata

| Spec Ref. | Feature                                                   | Implemented |
| --------- | --------------------------------------------------------- | :---------: |
| 12.2.2    | `/.well-known/openid-credential-issuer` discovery         |     ✅      |
| 12.2.2    | Unsigned metadata response (`application/json`)           |     ❌      |
| 12.2.3    | Signed metadata response (`application/jwt`)              |     ❌      |
| 12.2.2    | `Accept-Language` / `Content-Language` negotiation        |     ❌      |
| 12.2.4    | `credential_issuer` parameter                             |     ✅      |
| 12.2.4    | `authorization_servers` parameter                         |     ❌      |
| 12.2.4    | `credential_endpoint` parameter                           |     ✅      |
| 12.2.4    | `nonce_endpoint` parameter                                |     ✅      |
| 12.2.4    | `deferred_credential_endpoint` parameter                  |     ✅      |
| 12.2.4    | `notification_endpoint` parameter                         |     ✅      |
| 12.2.4    | `credential_request_encryption` parameter                 |     ❌      |
| 12.2.4    | `credential_response_encryption` parameter                |     ❌      |
| 12.2.4    | `batch_credential_issuance` parameter (with `batch_size`) |     ✅      |
| 12.2.4    | `display` parameter (issuer-level)                        |     ✅      |
| 12.2.4    | `credential_configurations_supported` object              |     ✅      |

### §12.3 — OAuth 2.0 Authorization Server Metadata

| Spec Ref. | Feature                                                     | Implemented |
| --------- | ----------------------------------------------------------- | :---------: |
| 12.3      | `pre-authorized_grant_anonymous_access_supported` parameter |     ✅      |

## Appendix D — Key Attestations

| Spec Ref. | Feature                                           | Implemented |
| --------- | ------------------------------------------------- | :---------: |
| D.1       | Key Attestation in JWT format                     |     ❌      |
| D.1       | `attested_keys` claim                             |     ❌      |
| D.1       | `key_storage` / `user_authentication` claims      |     ❌      |
| D.2       | Attack Potential Resistance values (iso*18045*\*) |     ❌      |

## Appendix E — Wallet Attestations

| Spec Ref. | Feature                                 | Implemented |
| --------- | --------------------------------------- | :---------: |
| E         | Wallet Attestation in JWT format        |     ❌      |
| E         | Attestation-Based Client Authentication |     ❌      |
| E         | Client Attestation PoP JWT              |     ❌      |
