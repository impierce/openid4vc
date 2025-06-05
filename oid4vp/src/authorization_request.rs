use crate::dcql::dcql_query::DcqlQuery;
use crate::oid4vp::OID4VP;
use anyhow::{anyhow, Result};
use dif_presentation_exchange::presentation_definition::ClaimFormatProperty;
use dif_presentation_exchange::ClaimFormatDesignation;
use is_empty::IsEmpty;
use monostate::MustBe;
use oid4vc_core::authorization_request::Object;
use oid4vc_core::builder_fn;
use oid4vc_core::{
    authorization_request::AuthorizationRequest, client_metadata::ClientMetadataResource, scope::Scope, RFC7519Claims,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Client Identifier Prefixes as defined in the OpenID4VP specification
/// See: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdPrefix {
    #[serde(rename = "pre-registered")]
    PreRegistered,
    #[serde(rename = "redirect_uri")]
    RedirectUri,
    #[serde(rename = "openid_federation")]
    OpenIDFederation,
    #[serde(rename = "decentralized_identifier")]
    DecentralizedIdentifier,
    #[serde(rename = "verifier_attestation")]
    VerifierAttestation,
    #[serde(rename = "x509_san_dns")]
    X509SanDns,
    #[serde(rename = "x509_hash")]
    X509Hash,
}

/// [`AuthorizationRequest`] claims specific to [`OID4VP`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequestParameters {
    pub response_type: MustBe!("vp_token"),
    pub dcql_query: Option<DcqlQuery>,
    pub client_id_prefix: Option<ClientIdPrefix>,
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
    client_id_prefix: Option<ClientIdPrefix>,
    client_id: Option<String>,
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
    builder_fn!(client_id, String);
    builder_fn!(scope, Scope);
    builder_fn!(redirect_uri, url::Url);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadataResource<ClientMetadataParameters>);
    builder_fn!(state, String);
    builder_fn!(dcql_query, DcqlQuery);
    builder_fn!(client_id_prefix, ClientIdPrefix);
    builder_fn!(custom_url_scheme, String);

    pub fn build(mut self) -> Result<AuthorizationRequest<Object<OID4VP>>> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
                    response_type: MustBe!("vp_token"),
                    dcql_query: self.dcql_query.take(),
                    client_id_prefix: self.client_id_prefix.take(),
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
                        client_id,
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
    use jsonwebtoken::Algorithm;
    use serde_json::from_str;

    #[test]
    fn test_client_id_scheme() {
        assert_eq!(
            ClientIdPrefix::PreRegistered,
            serde_json::from_str::<ClientIdPrefix>("\"pre-registered\"").unwrap()
        );
        assert_eq!(
            ClientIdPrefix::RedirectUri,
            serde_json::from_str::<ClientIdPrefix>("\"redirect_uri\"").unwrap()
        );
        assert_eq!(
            ClientIdPrefix::OpenIDFederation,
            serde_json::from_str::<ClientIdPrefix>("\"openid_federation\"").unwrap()
        );
        assert_eq!(
            ClientIdPrefix::DecentralizedIdentifier,
            serde_json::from_str::<ClientIdPrefix>("\"decentralized_identifier\"").unwrap()
        );
        assert_eq!(
            ClientIdPrefix::VerifierAttestation,
            serde_json::from_str::<ClientIdPrefix>("\"verifier_attestation\"").unwrap()
        );
        assert_eq!(
            ClientIdPrefix::X509SanDns,
            serde_json::from_str::<ClientIdPrefix>("\"x509_san_dns\"").unwrap()
        );
        assert_eq!(
            ClientIdPrefix::X509Hash,
            serde_json::from_str::<ClientIdPrefix>("\"x509_hash\"").unwrap()
        );
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
            // pub presentation_definition: PresentationDefinition,
            pub client_id_scheme: Option<String>,
            pub response_mode: Option<String>,
            pub scope: Option<Scope>,
            // pub nonce: String,
            // TODO: impl client_metadata_uri.
            #[serde(flatten)]
            pub client_metadata: Option<ClientMetadataResource<ClientMetadataParameters>>,
        }

        assert_eq!(
            ExampleAuthorizationRequest {
                client_id: "did:example:123".to_string(),
                redirect_uri: url::Url::parse("https://client.example.org/callback").unwrap(),
                response_type: MustBe!("vp_token id_token"),
                client_id_scheme: None,
                response_mode: None,
                scope: None,
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
            },
            from_str::<ExampleAuthorizationRequest>(include_str!(
                "../tests/examples/client_metadata/client_client_id_did.json"
            ))
            .unwrap()
        );
    }
}
