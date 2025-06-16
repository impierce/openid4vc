use crate::dcql::dcql_query::DcqlQuery;
use crate::oid4vp::OID4VP;

use anyhow::{anyhow, Result};
use dcql_oid4vc_core::authorization_request::Object;
use dcql_oid4vc_core::builder_fn;
use dcql_oid4vc_core::{
    authorization_request::AuthorizationRequest, client_metadata::ClientMetadataResource, scope::Scope, RFC7519Claims,
};
use dif_presentation_exchange::presentation_definition::ClaimFormatProperty;
use dif_presentation_exchange::ClaimFormatDesignation;
use is_empty::IsEmpty;
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use strum::Display;

#[derive(Debug, Clone, PartialEq)]
pub struct ClientId {
    prefix: ClientIdPrefix,
    identifier: String,
}

/// The Client ID Scheme enables the use of different mechanisms to obtain and validate the Verifier's metadata. As
/// described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-managemen
#[derive(Serialize, Deserialize, Debug, PartialEq, Display, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdPrefix {
    #[serde(rename = "pre-registered")]
    PreRegistered,
    RedirectUri,
    OpenidFederation,
    DecentralizedIdentifier,
    VerifierAttestation,
    X509SanDns,
    X509SanUri,
}

impl ClientId {
    pub fn new(prefix: ClientIdPrefix, identifier: String) -> Self {
        Self { prefix, identifier }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some((prefix_str, identifier)) = s.split_once(':') {
            let prefix = match prefix_str {
                "pre-registered" => ClientIdPrefix::PreRegistered,
                "redirect_uri" => ClientIdPrefix::RedirectUri,
                "openid_federation" => ClientIdPrefix::OpenidFederation,
                "did" => ClientIdPrefix::DecentralizedIdentifier,
                "verifier_attestation" => ClientIdPrefix::VerifierAttestation,
                "x509_san_dns" => ClientIdPrefix::X509SanDns,
                "x509_san_uri" => ClientIdPrefix::X509SanUri,
                _ => return Err(format!("Unknown client ID prefix: {}", prefix_str)),
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

    pub fn prefix(&self) -> &ClientIdPrefix {
        &self.prefix
    }
    pub fn identifier(&self) -> &str {
        &self.identifier
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

/// [`AuthorizationRequest`] claims specific to [`OID4VP`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequestParameters {
    pub response_type: MustBe!("vp_token"),
    pub dcql_query: DcqlQuery,
    pub response_mode: Option<String>,
    pub scope: Option<Scope>,
    pub nonce: String,
    #[serde(flatten)]
    pub client_metadata: ClientMetadataResource<ClientMetadataParameters>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ClientMetadataParameters {
    /// Object defining the formats and proof types of Verifiable Presentations and Verifiable Credentials that a
    /// Verifier supports.
    /// As described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-additional-verifier-metadat
    pub vp_formats: HashMap<ClaimFormatDesignation, ClaimFormatProperty>,
}

#[derive(Debug, Default, IsEmpty)]
pub struct AuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    dcql_query: Option<DcqlQuery>,
    client_id: Option<ClientId>,
    redirect_uri: Option<url::Url>,
    state: Option<String>,
    scope: Option<Scope>,
    response_mode: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadataResource<ClientMetadataParameters>>,
    custom_url_scheme: Option<String>,
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
    builder_fn!(redirect_uri, url::Url);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadataResource<ClientMetadataParameters>);
    builder_fn!(state, String);
    builder_fn!(dcql_query, DcqlQuery);
    builder_fn!(custom_url_scheme, String);

    pub fn build(mut self) -> Result<AuthorizationRequest<Object<OID4VP>>> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
                    response_type: MustBe!("vp_token"),
                    dcql_query: self
                        .dcql_query
                        .take()
                        .ok_or_else(|| anyhow!("presentation_definition parameter is required."))?,
                    // client_id_scheme: self.client_id_scheme.take(),
                    scope: self.scope.take(),
                    response_mode: self.response_mode.take(),
                    nonce: self
                        .nonce
                        .take()
                        .ok_or_else(|| anyhow!("nonce parameter is required."))?,
                    client_metadata: self
                        .client_metadata
                        .take()
                        .ok_or_else(|| anyhow!("client_metadata or client_metadata_uri is required."))?,
                };

                Ok(AuthorizationRequest::<Object<OID4VP>> {
                    custom_url_scheme: self.custom_url_scheme.take().unwrap_or("openid".to_string()),
                    body: Object::<OID4VP> {
                        rfc7519_claims: self.rfc7519_claims,
                        client_id: client_id.to_string(),
                        redirect_uri: self
                            .redirect_uri
                            .take()
                            .ok_or_else(|| anyhow!("redirect_uri parameter is required."))?,
                        state: self.state.take(),
                        extension,
                    },
                })
            }
            _ => Err(anyhow!(
                "one of either request_uri, request or other parameters should be set"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcql::dcql_query::{
        ClaimPath, ClaimPathElement, ClaimQuery, CredentialId, CredentialQuery, DcqlQuery, Format, MetaTypes,
    };
    use jsonwebtoken::Algorithm;
    use serde_json::from_str;

    fn test_credential_id(id: &str) -> CredentialId {
        CredentialId::try_new(id.to_string()).unwrap()
    }

    fn test_claim_path(elements: Vec<ClaimPathElement>) -> ClaimPath {
        ClaimPath::try_new(elements).unwrap()
    }

    #[test]
    fn test_new_client_id() {
        let test_client_id = ClientId::parse("openid_federation:example_client").unwrap();
        assert_eq!(test_client_id.prefix(), &ClientIdPrefix::OpenidFederation);
        assert_eq!(test_client_id.identifier(), "example_client");
    }

    #[test]
    fn test_redirect_client_id() {
        let test_redirect_id = ClientId::parse("example_client").unwrap();
        assert_eq!(test_redirect_id.prefix(), &ClientIdPrefix::PreRegistered);
        assert_eq!(test_redirect_id.identifier(), "example_client");
    }

    #[test]
    fn test_oid4vp_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VP/tree/965597ae01fc6e6a2bddc0d6b16f3f6122f3c1ab/examples/client_metadata.

        // Some required parameters are omitted in the examples. Therefore this example struct represents a subset of
        // the full `AuthorizationRequestParameters` struct.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct ExampleAuthorizationRequest {
            pub client_id: String,
            pub redirect_uri: url::Url,
            pub response_type: MustBe!("vp_token id_token"),
            pub dcql_query: DcqlQuery,
            pub response_mode: Option<String>,
            pub scope: Option<Scope>,
            pub nonce: String,
            // TODO: impl client_metadata_uri.
            #[serde(flatten)]
            pub client_metadata: Option<ClientMetadataResource<ClientMetadataParameters>>,
        }

        assert_eq!(
            ExampleAuthorizationRequest {
                client_id: "did:example:123".to_string(),
                redirect_uri: url::Url::parse("https://client.example.org/callback").unwrap(),
                response_type: MustBe!("vp_token id_token"),
                nonce: "n-0S6_WzA2Mj".to_string(),
                client_metadata: Some(ClientMetadataResource::ClientMetadata {
                    client_name: Some("My Example (SIOP)".to_string()),
                    logo_uri: None,
                    extension: ClientMetadataParameters {
                        vp_formats: vec![
                            (
                                ClaimFormatDesignation::JwtVpJson,
                                ClaimFormatProperty::Alg(vec![Algorithm::EdDSA, Algorithm::ES256,])
                            ),
                            (
                                ClaimFormatDesignation::LdpVp,
                                ClaimFormatProperty::ProofType(vec!["Ed25519Signature2018".to_string(),])
                            )
                        ]
                        .into_iter()
                        .collect()
                    },
                    other: HashMap::from_iter(vec![("application_type".to_string(), serde_json::json!("web"))]),
                }),
                dcql_query: DcqlQuery {
                    credentials: vec![CredentialQuery {
                        id: test_credential_id("my_credential"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("last_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("first_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    }],
                    credential_sets: None
                },
                response_mode: None,
                scope: None,
            },
            from_str::<ExampleAuthorizationRequest>(include_str!(
                "../tests/examples/authorization_request_chayatest.json"
            ))
            .unwrap()
        );
    }
}
