use crate::oid4vp::OID4VP;
use anyhow::{anyhow, Result};
use dif_presentation_exchange::presentation_definition::ClaimFormatProperty;
use dif_presentation_exchange::{ClaimFormatDesignation, PresentationDefinition};
use is_empty::IsEmpty;
use monostate::MustBe;
use oid4vc_core::authorization_request::Object;
use oid4vc_core::builder_fn;
use oid4vc_core::{
    authorization_request::AuthorizationRequest, client_metadata::ClientMetadataEnum, scope::Scope, RFC7519Claims,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The Client ID Scheme enables the use of different mechanisms to obtain and validate the Verifier's metadata. As
/// described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-managemen.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ClientIdScheme {
    #[serde(rename = "pre-registered")]
    PreRegistered,
    RedirectUri,
    EntityId,
    Did,
    VerifierAttestation,
    X509SanDns,
    X509SanUri,
}

/// [`AuthorizationRequest`] claims specific to [`OID4VP`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequestParameters {
    pub response_type: MustBe!("vp_token"),
    pub presentation_definition: PresentationDefinition,
    pub client_id_scheme: Option<ClientIdScheme>,
    pub response_mode: Option<String>,
    pub scope: Option<Scope>,
    pub nonce: String,
    // TODO: impl client_metadata_uri.
    #[serde(flatten)]
    pub client_metadata: Option<ClientMetadataEnum<ClientMetadataParameters>>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ClientMetadataParameters {
    /// Object defining the formats and proof types of Verifiable Presentations and Verifiable Credentials that a
    /// Verifier supports.
    /// As described here: https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-additional-verifier-metadat.
    vp_formats: HashMap<ClaimFormatDesignation, ClaimFormatProperty>,
}

#[derive(Debug, Default, IsEmpty)]
pub struct AuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    presentation_definition: Option<PresentationDefinition>,
    client_id_scheme: Option<ClientIdScheme>,
    client_id: Option<String>,
    redirect_uri: Option<url::Url>,
    state: Option<String>,
    scope: Option<Scope>,
    response_mode: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadataEnum<ClientMetadataParameters>>,
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
    builder_fn!(client_metadata, ClientMetadataEnum<ClientMetadataParameters>);
    builder_fn!(state, String);
    builder_fn!(presentation_definition, PresentationDefinition);
    builder_fn!(client_id_scheme, ClientIdScheme);

    pub fn build(mut self) -> Result<AuthorizationRequest<Object<OID4VP>>> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
                    response_type: MustBe!("vp_token"),
                    presentation_definition: self
                        .presentation_definition
                        .take()
                        .ok_or_else(|| anyhow!("presentation_definition parameter is required."))?,
                    client_id_scheme: self.client_id_scheme.take(),
                    scope: self.scope.take(),
                    response_mode: self.response_mode.take(),
                    nonce: self
                        .nonce
                        .take()
                        .ok_or_else(|| anyhow!("nonce parameter is required."))?,
                    client_metadata: self.client_metadata.take(),
                };

                Ok(AuthorizationRequest::<Object<OID4VP>> {
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
    use std::{fs::File, path::Path};

    use serde::de::DeserializeOwned;

    use super::*;

    fn json_example<T>(path: &str) -> T
    where
        T: DeserializeOwned,
    {
        let file_path = Path::new(path);
        let file = File::open(file_path).expect("file does not exist");
        serde_json::from_reader::<_, T>(file).expect("could not parse json")
    }

    #[test]
    fn test_client_id_scheme() {
        assert_eq!(
            ClientIdScheme::PreRegistered,
            serde_json::from_str::<ClientIdScheme>("\"pre-registered\"").unwrap()
        );
        assert_eq!(
            ClientIdScheme::RedirectUri,
            serde_json::from_str::<ClientIdScheme>("\"redirect_uri\"").unwrap()
        );
        assert_eq!(
            ClientIdScheme::EntityId,
            serde_json::from_str::<ClientIdScheme>("\"entity_id\"").unwrap()
        );
        assert_eq!(
            ClientIdScheme::Did,
            serde_json::from_str::<ClientIdScheme>("\"did\"").unwrap()
        );
        assert_eq!(
            ClientIdScheme::VerifierAttestation,
            serde_json::from_str::<ClientIdScheme>("\"verifier_attestation\"").unwrap()
        );
        assert_eq!(
            ClientIdScheme::X509SanDns,
            serde_json::from_str::<ClientIdScheme>("\"x509_san_dns\"").unwrap()
        );
        assert_eq!(
            ClientIdScheme::X509SanUri,
            serde_json::from_str::<ClientIdScheme>("\"x509_san_uri\"").unwrap()
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
            pub client_metadata: Option<ClientMetadataEnum<ClientMetadataParameters>>,
        }

        assert_eq!(
            ExampleAuthorizationRequest {
                client_id: "did:example:123".to_string(),
                redirect_uri: url::Url::parse("https://client.example.org/callback").unwrap(),
                response_type: MustBe!("vp_token id_token"),
                client_id_scheme: None,
                response_mode: None,
                scope: None,
                client_metadata: Some(ClientMetadataEnum::ClientMetadata {
                    client_name: Some("My Example (SIOP)".to_string()),
                    logo_uri: None,
                    extension: ClientMetadataParameters {
                        vp_formats: vec![
                            (
                                ClaimFormatDesignation::JwtVpJson,
                                ClaimFormatProperty::Alg(vec!["EdDSA".to_string(), "ES256K".to_string(),])
                            ),
                            (
                                ClaimFormatDesignation::LdpVp,
                                ClaimFormatProperty::ProofType(vec!["Ed25519Signature2018".to_string(),])
                            )
                        ]
                        .into_iter()
                        .collect()
                    }
                }),
            },
            json_example::<ExampleAuthorizationRequest>("tests/examples/client_metadata/client_client_id_did.json")
        );
    }
}
