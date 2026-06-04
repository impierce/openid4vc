use crate::dcql::dcql_query::DcqlQuery;
use crate::oid4vp::OID4VP;
use anyhow::{anyhow, Result};
use is_empty::IsEmpty;
use jsonwebtoken::Algorithm;
use monostate::MustBe;
use nutype::nutype;
use oid4vc_core::authorization_request::{Object, RedirectOrResponseUri};
use oid4vc_core::builder_fn;
use oid4vc_core::utils::predicates::not_empty;
use oid4vc_core::{
    authorization_request::AuthorizationRequest, client_metadata::ClientMetadataResource, scope::Scope, RFC7519Claims,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::fmt;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub struct ClientId {
    prefix: ClientIdPrefix,
    identifier: String,
}

/// The Client ID Scheme enables the use of different mechanisms to obtain and validate the Verifier's metadata. As
/// described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an
#[derive(Debug, PartialEq, Clone)]
pub enum ClientIdPrefix {
    PreRegistered,
    RedirectUri,
    OpenidFederation,
    DecentralizedIdentifier,
    VerifierAttestation,
    X509SanDns,
    X509Hash,
}

impl std::fmt::Display for ClientIdPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientIdPrefix::PreRegistered => write!(f, "pre-registered"),
            ClientIdPrefix::RedirectUri => write!(f, "response_uri"),
            ClientIdPrefix::OpenidFederation => write!(f, "openid_federation"),
            ClientIdPrefix::DecentralizedIdentifier => write!(f, "decentralized_identifier"),
            ClientIdPrefix::VerifierAttestation => write!(f, "verifier_attestation"),
            ClientIdPrefix::X509SanDns => write!(f, "x509_san_dns"),
            ClientIdPrefix::X509Hash => write!(f, "x509_hash"),
        }
    }
}

impl ClientId {
    pub fn new(prefix: ClientIdPrefix, identifier: String) -> Self {
        Self { prefix, identifier }
    }
    pub fn prefix(&self) -> &ClientIdPrefix {
        &self.prefix
    }
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl std::str::FromStr for ClientId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((prefix_str, identifier)) = s.split_once(':') {
            let prefix = match prefix_str {
                "pre-registered" => ClientIdPrefix::PreRegistered,
                "response_uri" => ClientIdPrefix::RedirectUri,
                "openid_federation" => ClientIdPrefix::OpenidFederation,
                "decentralized_identifier" => ClientIdPrefix::DecentralizedIdentifier,
                "verifier_attestation" => ClientIdPrefix::VerifierAttestation,
                "x509_san_dns" => ClientIdPrefix::X509SanDns,
                "x509_hash" => ClientIdPrefix::X509Hash,
                _ => return Err(format!("Unknown client ID prefix: {prefix_str}")),
            };
            Ok(Self {
                prefix,
                identifier: identifier.to_string(),
            })
        } else {
            Ok(Self {
                prefix: ClientIdPrefix::PreRegistered, // defaults to PreRegistered if no prefix is provided
                identifier: s.to_string(),
            })
        }
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.prefix {
            ClientIdPrefix::PreRegistered => write!(f, "{}", self.identifier),
            _ => write!(f, "{}:{}", self.prefix, self.identifier),
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormatIdentifier {
    JwtVcJson,
    JwtVpJson,
    LdpVc,
    LdpVp,
    MsoMdoc,
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
}

/// [`AuthorizationRequest`] claims specific to [`OID4VP`] and as defined in the spec: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequestParameters {
    pub response_type: MustBe!("vp_token"),
    // TODO: Implement support for other response types. Currently only vp_token is supported.
    pub dcql_query: DcqlQuery,
    pub response_mode: String,
    pub scope: Option<Scope>,
    pub nonce: String,
    #[serde(flatten)]
    pub client_metadata: ClientMetadataResource<ClientMetadataParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<TransactionData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_info: Option<VerifierInfo>,
    // TODO: When support for `request_uri` is added, this field should be used to indicate the HTTP method to retrieve the request object from the `request_uri`.
    // We must then add validation to ensure that `request_uri_method` is only set when `request_uri` is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_method: Option<RequestUriMethod>,
}

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, PartialEq, Clone, Serialize, Deserialize)
)]
pub struct TransactionData(Vec<String>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct VerifierInfoAttestation {
    pub format: String,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ids: Option<CredentialIds>,
}

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, PartialEq, Clone, Serialize, Deserialize)
)]
pub struct VerifierInfo(Vec<VerifierInfoAttestation>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum RequestUriMethod {
    Get,
    Post,
}
#[nutype(
    validate(predicate = not_empty),
    derive(Debug, PartialEq, Clone, Serialize, Deserialize)
)]
pub struct CredentialIds(Vec<String>);

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, PartialEq, Clone, Serialize, Deserialize)
)]
pub struct EncryptedResponseEncValues(Vec<String>);

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default)]
pub struct ClientMetadataParameters {
    /// Object defining the formats and proof types of Verifiable Presentations and Verifiable Credentials that a
    /// Verifier supports.
    /// As described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-additional-wallet-metadata-
    pub vp_formats_supported: VpFormatsSupported,
    /// TODO: Implement encryption response support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_response_enc_values_supported: Option<EncryptedResponseEncValues>,
    /// TODO: Not yet implemented. Requires further implementation of a JWK library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JsonWebKeySet>,
}

// TODO: Temporary placeholder structure until we add a proper JWK library
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

// TODO: Temporary placeholder structure until we add a proper JWK library.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct JsonWebKey {
    pub kid: String,
}

#[skip_serializing_none]
#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct VpFormatsSupported {
    pub jwt_vc_json: Option<JwtVcJsonParameters>,
    pub jwt_vp_json: Option<JwtVpJsonParameters>,
    #[serde(rename = "dc+sd-jwt")]
    pub dc_sd_jwt: Option<DcSdJwtParameters>,
    #[serde(rename = "vc+sd-jwt")]
    pub vc_sd_jwt: Option<VcSdJwtParameters>,
    pub ldp_vc: Option<LdpVcParameters>,
    pub di_vp: Option<DiVpParameters>,
    pub mso_mdoc: Option<MsoMdocParameters>,
}

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, PartialEq, Clone, Serialize, Deserialize)
)]
pub struct AlgValues(Vec<Algorithm>);

#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
pub struct JwtVcJsonParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values: Option<AlgValues>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct JwtVpJsonParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_values: Option<AlgValues>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct DcSdJwtParameters {
    #[serde(rename = "sd-jwt_alg_values", skip_serializing_if = "Option::is_none")]
    pub sd_jwt_alg_values: Option<AlgValues>,
    #[serde(rename = "kb-jwt_alg_values", skip_serializing_if = "Option::is_none")]
    pub kb_jwt_alg_values: Option<AlgValues>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct VcSdJwtParameters {
    #[serde(rename = "sd-jwt_alg_values", skip_serializing_if = "Option::is_none")]
    pub sd_jwt_alg_values: Option<AlgValues>,
    #[serde(rename = "kb-jwt_alg_values", skip_serializing_if = "Option::is_none")]
    pub kb_jwt_alg_values: Option<AlgValues>,
}

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, PartialEq, Clone, Serialize, Deserialize)
)]
pub struct ProofTypeValues(Vec<String>);

#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct LdpVcParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type_values: Option<ProofTypeValues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite_values: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct DiVpParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptosuite_values: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Clone, Serialize)]
pub struct MsoMdocParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuerauth_alg_values: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deviceauth_alg_values: Option<Vec<i32>>,
}

/// Builder for the Authorization Request as defined in the spec: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request
/// NOTE: this Authorization Request is not to be confused with the same-named request in OpenID for Verifiable Credential Issuance.
#[derive(Debug, Default, IsEmpty)]
pub struct AuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    dcql_query: Option<DcqlQuery>,
    client_id: Option<ClientId>,
    response_uri: Option<Url>,
    // FIX! TODO: Make sure state is required when presentations are requested WITHOUT holder binding proofs.
    state: Option<String>,
    scope: Option<Scope>,
    response_mode: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadataResource<ClientMetadataParameters>>,
    custom_url_scheme: Option<String>,
    transaction_data: Option<TransactionData>,
    verifier_info: Option<VerifierInfo>,
    request_uri_method: Option<RequestUriMethod>,
}

impl AuthorizationRequestBuilder {
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(response_mode, String);
    builder_fn!(client_id, ClientId);
    builder_fn!(scope, Scope);
    builder_fn!(response_uri, Url);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadataResource<ClientMetadataParameters>);
    builder_fn!(state, String);
    builder_fn!(dcql_query, DcqlQuery);
    builder_fn!(custom_url_scheme, String);
    builder_fn!(transaction_data, TransactionData);
    builder_fn!(verifier_info, VerifierInfo);
    builder_fn!(request_uri_method, RequestUriMethod);

    pub fn build(mut self) -> Result<AuthorizationRequest<Object<OID4VP>>> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow!("`client_id` parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
                    response_type: MustBe!("vp_token"),
                    dcql_query: self
                        .dcql_query
                        .take()
                        .ok_or_else(|| anyhow!("`dcql_query` parameter is required."))?,
                    scope: self.scope.take(),
                    response_mode: self
                        .response_mode
                        .take()
                        .ok_or_else(|| anyhow!("`response_mode` parameter is required."))?,
                    nonce: self
                        .nonce
                        .take()
                        .ok_or_else(|| anyhow!("`nonce` parameter is required."))?,
                    client_metadata: self
                        .client_metadata
                        .take()
                        .ok_or_else(|| anyhow!("`client_metadata` or `client_metadata_uri` is required."))?,
                    transaction_data: self.transaction_data.take(),
                    verifier_info: self.verifier_info.take(),
                    request_uri_method: self.request_uri_method.take(),
                };

                Ok(AuthorizationRequest::<Object<OID4VP>> {
                    custom_url_scheme: self.custom_url_scheme.take().unwrap_or("openid".to_string()),
                    body: Object::<OID4VP> {
                        rfc7519_claims: self.rfc7519_claims,
                        client_id: client_id.to_string(),
                        uri: RedirectOrResponseUri::ResponseUri(
                            self.response_uri
                                .take()
                                .ok_or_else(|| anyhow!("`response_uri` parameter is required."))?,
                        ),
                        state: self.state.take(),
                        extension,
                    },
                })
            }
            _ => Err(anyhow!(
                "one of either `request_uri`, `request` or other parameters should be set"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn test_new_client_id() {
        let test_client_id = "openid_federation:example_client".parse::<ClientId>().unwrap();
        assert_eq!(test_client_id.prefix(), &ClientIdPrefix::OpenidFederation);
        assert_eq!(test_client_id.identifier(), "example_client");
    }

    #[test]
    fn test_redirect_client_id() {
        let test_redirect_id = "example_client".parse::<ClientId>().unwrap();
        assert_eq!(test_redirect_id.prefix(), &ClientIdPrefix::PreRegistered);
        assert_eq!(test_redirect_id.identifier(), "example_client");
    }

    #[test]
    fn test_client_metadata_parameters_jwt_vc_json() {
        let build: AuthorizationRequestBuilder = AuthorizationRequestBuilder::default()
            .client_id(ClientId::from_str("decentralized_identifier:example:123").unwrap())
            .response_uri(url::Url::parse("https://client.example.org/callback").unwrap())
            .nonce("n-0S6_WzA2Mj".to_string())
            .client_metadata(ClientMetadataResource::ClientMetadata {
                client_name: Some("My SimpleSample".to_string()),
                logo_uri: None,
                extension: ClientMetadataParameters {
                    vp_formats_supported: VpFormatsSupported {
                        jwt_vc_json: Some(JwtVcJsonParameters {
                            alg_values: Some(AlgValues::try_new(vec![Algorithm::ES256, Algorithm::ES384]).unwrap()),
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                other: HashMap::new(),
            });
        let expected = from_str::<ClientMetadataParameters>(include_str!(
            "../tests/examples/client_metadata/examples/client_metadata/w3c_jwt_verifier_metadata.json"
        ))
        .unwrap();

        let auth_metadata = match build.client_metadata.as_ref().unwrap() {
            ClientMetadataResource::ClientMetadata { extension, .. } => extension,
            ClientMetadataResource::ClientMetadataUri { .. } => panic!(),
        };

        assert_eq!(auth_metadata, &expected);
    }

    #[test]
    fn test_client_metadata_parameters_sd_jwt_vc() {
        let build: AuthorizationRequestBuilder = AuthorizationRequestBuilder::default()
            .client_id(ClientId::from_str("decentralized_identifier:example:123").unwrap())
            .response_uri(url::Url::parse("https://client.example.org/callback").unwrap())
            .nonce("n-0S6_WzA2Mj".to_string())
            .client_metadata(ClientMetadataResource::ClientMetadata {
                client_name: Some("My SimpleSample".to_string()),
                logo_uri: None,
                extension: ClientMetadataParameters {
                    vp_formats_supported: VpFormatsSupported {
                        dc_sd_jwt: Some(DcSdJwtParameters {
                            sd_jwt_alg_values: Some(
                                AlgValues::try_new(vec![Algorithm::ES256, Algorithm::ES384]).unwrap(),
                            ),
                            kb_jwt_alg_values: Some(
                                AlgValues::try_new(vec![Algorithm::ES256, Algorithm::ES384]).unwrap(),
                            ),
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                other: HashMap::new(),
            });
        let expected = from_str::<ClientMetadataParameters>(include_str!(
            "../tests/examples/client_metadata/examples/client_metadata/sd_jwt_vc_verifier_metadata.json"
        ))
        .unwrap();

        let auth_metadata = match build.client_metadata.as_ref().unwrap() {
            ClientMetadataResource::ClientMetadata { extension, .. } => extension,
            ClientMetadataResource::ClientMetadataUri { .. } => panic!(),
        };

        assert_eq!(auth_metadata, &expected);
    }

    #[test]
    fn test_client_metadata_parameters_w3c_ldp_vc() {
        let build: AuthorizationRequestBuilder = AuthorizationRequestBuilder::default()
            .client_id(ClientId::from_str("decentralized_identifier:example:123").unwrap())
            .response_uri(url::Url::parse("https://client.example.org/callback").unwrap())
            .nonce("n-0S6_WzA2Mj".to_string())
            .client_metadata(ClientMetadataResource::ClientMetadata {
                client_name: Some("My SimpleSample".to_string()),
                logo_uri: None,
                extension: ClientMetadataParameters {
                    vp_formats_supported: VpFormatsSupported {
                        ldp_vc: Some(LdpVcParameters {
                            proof_type_values: Some(
                                ProofTypeValues::try_new(vec![
                                    "DataIntegrityProof".to_string(),
                                    "Ed25519Signature2020".to_string(),
                                ])
                                .unwrap(),
                            ),
                            cryptosuite_values: Some(vec![
                                "ecdsa-rdfc-2019".to_string(),
                                "ecdsa-sd-2023".to_string(),
                                "ecdsa-jcs-2019".to_string(),
                                "bbs-2023".to_string(),
                            ]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                other: HashMap::new(),
            });
        let expected = from_str::<ClientMetadataParameters>(include_str!(
            "../tests/examples/client_metadata/examples/client_metadata/w3c_ldp_verifier_metadata.json"
        ))
        .unwrap();

        let auth_metadata = match build.client_metadata.as_ref().unwrap() {
            ClientMetadataResource::ClientMetadata { extension, .. } => extension,
            ClientMetadataResource::ClientMetadataUri { .. } => panic!(),
        };

        assert_eq!(auth_metadata, &expected);
    }

    #[test]
    fn test_client_metadata_parameters_mso_mdoc_verifier() {
        let build: AuthorizationRequestBuilder = AuthorizationRequestBuilder::default()
            .client_id(ClientId::from_str("decentralized_identifier:example:123").unwrap())
            .response_uri(url::Url::parse("https://client.example.org/callback").unwrap())
            .nonce("n-0S6_WzA2Mj".to_string())
            .client_metadata(ClientMetadataResource::ClientMetadata {
                client_name: Some("My SimpleSample".to_string()),
                logo_uri: None,
                extension: ClientMetadataParameters {
                    vp_formats_supported: VpFormatsSupported {
                        mso_mdoc: Some(MsoMdocParameters {
                            issuerauth_alg_values: Some(vec![-9, -50]),
                            deviceauth_alg_values: Some(vec![-9, -50]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                other: HashMap::new(),
            });
        let expected = from_str::<ClientMetadataParameters>(include_str!(
            "../tests/examples/client_metadata/examples/client_metadata/mso_mdoc_verifier_metadata.json"
        ))
        .unwrap();

        let auth_metadata = match build.client_metadata.as_ref().unwrap() {
            ClientMetadataResource::ClientMetadata { extension, .. } => extension,
            ClientMetadataResource::ClientMetadataUri { .. } => panic!(),
        };

        assert_eq!(auth_metadata, &expected);
    }

    #[test]
    fn test_encrypted_response_enc_values_non_empty() {
        let valid = EncryptedResponseEncValues::try_new(vec!["A128GCM".to_string(), "A256GCM".to_string()]);
        assert!(valid.is_ok());

        let invalid = EncryptedResponseEncValues::try_new(vec![]);
        assert!(invalid.is_err());
    }
}
