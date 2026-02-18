use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::{AuthorizationRequest, CodeChallengeMethod};
use crate::authorization_response::AuthorizationResponse;
use crate::credential_issuer::credential_configurations_supported::{
    AlgIdentifier, CredentialConfigurationsSupportedObject,
};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::CredentialOfferParameters;
use crate::credential_request::{CredentialIdentifierOrCredentialConfigurationId, CredentialRequest};
use crate::nonce_response::NonceResponse;
use crate::notification_request::{NotificationEvent, NotificationRequest};
use crate::proof::ProofType;
use crate::proofs::Proofs;
use crate::Proof;
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::{anyhow, Result};
use jsonwebtoken::Algorithm;
use oid4vc_core::authentication::subject::SigningSubject;
use oid4vc_core::utils::form_urlencoded::to_form_urlencoded_string;
use oid4vc_core::SubjectSyntaxType;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use std::str::FromStr;

#[derive(Debug)]
pub struct Wallet {
    pub subject: SigningSubject,
    pub supported_subject_syntax_types: Vec<SubjectSyntaxType>,
    pub client: ClientWithMiddleware,
    pub proof_signing_alg_values_supported: Vec<Algorithm>,
}

// TODO: Move everything related to pushed authorization response to a separate module?
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

// TODO: Move everything related to pushed authorization response to a separate module?
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationRequestByReference {
    pub client_id: String,
    pub request_uri: String,
}

impl Wallet {
    pub fn new(
        subject: SigningSubject,
        supported_subject_syntax_types: Vec<impl TryInto<SubjectSyntaxType>>,
        proof_signing_alg_values_supported: Vec<Algorithm>,
    ) -> anyhow::Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(2);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Ok(Self {
            subject,
            supported_subject_syntax_types: supported_subject_syntax_types
                .into_iter()
                .map(|subject_syntax_type| {
                    subject_syntax_type
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid did method."))
                })
                .collect::<Result<_>>()?,
            client,
            proof_signing_alg_values_supported,
        })
    }

    pub async fn get_credential_offer(&self, credential_offer_uri: Url) -> Result<CredentialOfferParameters> {
        self.client
            .get(credential_offer_uri)
            .send()
            .await?
            .json::<CredentialOfferParameters>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential offer"))
    }

    pub async fn get_authorization_server_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata> {
        let mut oauth_authorization_server_endpoint = credential_issuer_url.clone();

        // According to RFC 8414, the path to the OAuth Authorization Server Metadata is formed by
        // appending `/.well-known/oauth-authorization-server` to the issuer's origin. If the issuer
        // URL contains a path, then that path must be appended to the well-known path.
        // See RFC 8414 Section 3: https://www.rfc-editor.org/rfc/rfc8414.html#section-3
        oauth_authorization_server_endpoint.set_path(&format!(
            "/.well-known/oauth-authorization-server{}",
            credential_issuer_url.path()
        ));

        oauth_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .pop_if_empty();

        let response = self.client.get(oauth_authorization_server_endpoint).send().await;

        if let Ok(response) = response {
            // If the request to the `oauth-authorization-server` endpoint is successful, return the metadata.
            if response.status().is_success() {
                return response
                    .json::<AuthorizationServerMetadata>()
                    .await
                    .map_err(|e| anyhow!("Failed to parse authorization server metadata: {}", e));
            }
        }

        // If the request to the `oauth-authorization-server` endpoint fails, fallback to the OpenID Provider Configuration endpoint.
        // See RFC 8414 Section 5: https://www.rfc-editor.org/rfc/rfc8414.html#section-5
        let mut openid_configuration_endpoint = credential_issuer_url.clone();

        openid_configuration_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .pop_if_empty()
            .push(".well-known")
            .push("openid-configuration");

        self.client
            .get(openid_configuration_endpoint)
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
            .map_err(|e| anyhow!("Failed to get metadata from both primary and fallback endpoints: {}", e))
    }

    pub async fn get_credential_issuer_metadata(&self, credential_issuer_url: Url) -> Result<CredentialIssuerMetadata> {
        let mut openid_credential_issuer_endpoint = credential_issuer_url.clone();
        let path = credential_issuer_url.path().trim_end_matches('/');
        openid_credential_issuer_endpoint.set_path(&format!("/.well-known/openid-credential-issuer{path}"));

        self.client
            .get(openid_credential_issuer_endpoint)
            .send()
            .await?
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential issuer metadata"))
    }

    // TODO: Move everything related to pushed authorization response to a separate module?
    // TODO: refactor to reduce the number of arguments
    #[allow(clippy::too_many_arguments)]
    pub async fn get_pushed_authorization_response(
        &self,
        pushed_authorization_request_endpoint: Url,
        client_id: &str,
        redirect_uri: Url,
        state: String,
        authorization_details: Vec<AuthorizationDetailsObject>,
        issuer_state: String,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
    ) -> Result<PushedAuthorizationResponse> {
        let authorization_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: Some(redirect_uri),
            // TODO: add support for `scope`
            scope: None,
            state: Some(state),
            authorization_details,
            issuer_state: Some(issuer_state),
            code_challenge,
            code_challenge_method,
        };

        let url_encoded = to_form_urlencoded_string(&authorization_request).unwrap();

        self.client
            .post(pushed_authorization_request_endpoint)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(url_encoded)
            .send()
            .await?
            .json::<PushedAuthorizationResponse>()
            .await
            .map_err(|err| anyhow::anyhow!("Failed to send pushed authorization request: {err}"))
    }

    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        _authorization_details: Vec<AuthorizationDetailsObject>,
        _code_challenge: Option<String>,
        _code_challenge_method: Option<String>,
        pushed_authorization_response: Option<PushedAuthorizationResponse>,
    ) -> Result<AuthorizationResponse> {
        let client_id = self
            .subject
            .identifier(
                &self
                    .supported_subject_syntax_types
                    .first()
                    .map(ToString::to_string)
                    .ok_or(anyhow!("No supported subject syntax types found."))?,
                self.proof_signing_alg_values_supported[0],
            )
            .await?;

        if let Some(pushed_response) = pushed_authorization_response {
            let authorization_request = AuthorizationRequestByReference {
                client_id,
                request_uri: pushed_response.request_uri,
            };

            return Ok(self
                .client
                .get(authorization_endpoint)
                .form(&authorization_request)
                .send()
                .await?
                .json::<AuthorizationResponse>()
                .await?);
        }

        // TODO: Support regular authorization request without pushed authorization request.
        Err(anyhow!(
            "Authorization code flow without pushed authorization request is not supported yet."
        ))
    }

    pub async fn get_access_token(&self, token_endpoint: Url, token_request: TokenRequest) -> Result<TokenResponse> {
        self.client
            .post(token_endpoint)
            .form(&token_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }

    // Select supported signing algorithm that matches the Credential Issuer's supported Proof Types.
    // Supplying the `proofs` parameter to the Credential Request is only required when the `proof_types_supported`
    // parameter is present in the Credential Configuration in the Credential Issuer's metadata. However, if the
    // `proof_types_supported` is not present, the Wallet will still provide the `proofs` signed with its own preferred
    // signing algorithm. For more information see: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
    fn select_signing_algorithm(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<Algorithm> {
        let proof_types_supported = &credential_configuration.proof_types_supported;

        // If the Credential Issuer does not define any supported Proof Types, then the Wallet will use its own default signing algorithm.
        if proof_types_supported.is_empty() {
            return self
                .proof_signing_alg_values_supported
                .first()
                .ok_or(anyhow::anyhow!("Wallet does not support any signing algorithms"))
                .cloned();
        }

        // Extract the actual signing algorithms if the Credential Issuer supports JWT proof types.
        // TODO: support Proof types other than Jwt.
        let credential_issuer_proof_signing_alg_values_supported = proof_types_supported
            .get(&ProofType::Jwt)
            .map(|proof_type| proof_type.proof_signing_alg_values_supported.clone())
            .ok_or(anyhow::anyhow!(
                "The Credential Issuer does not support JWT proof types"
            ))?;

        // Return the first signing algorithm that matches any of the Credential Issuer's supported signing algorithms.
        self.proof_signing_alg_values_supported
            .iter()
            .find(|supported_algorithm| {
                // Since `Algorithm` does not implement `Display`, we need to use `Debug` in order to convert it to a `String`.
                let supported_algorithm_str = format!("{supported_algorithm:?}");
                credential_issuer_proof_signing_alg_values_supported
                    .contains(&AlgIdentifier::String(supported_algorithm_str))
            })
            .cloned()
            .ok_or(anyhow::anyhow!("No matching supported signing algorithms found."))
    }

    fn select_subject_syntax_type(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<SubjectSyntaxType> {
        if !credential_configuration
            .cryptographic_binding_methods_supported
            .is_empty()
            && credential_configuration.proof_types_supported.is_empty()
        {
            return Err(anyhow::anyhow!("Proof types supported must be defined if cryptographic binding methods are defined in the credential configuration."));
        }

        let credential_issuer_cryptographic_binding_methods_supported: Vec<SubjectSyntaxType> =
            credential_configuration
                .cryptographic_binding_methods_supported
                .iter()
                .filter_map(|binding_method| SubjectSyntaxType::from_str(binding_method).ok())
                .collect();

        self.supported_subject_syntax_types
            .iter()
            .find(|supported_syntax_type| {
                credential_issuer_cryptographic_binding_methods_supported.contains(supported_syntax_type)
            })
            // If no match is found, use the first supported syntax type as a fallback.
            .or_else(|| self.supported_subject_syntax_types.first())
            .cloned()
            .ok_or(anyhow::anyhow!("No supported subject syntax types found."))
    }

    pub async fn get_nonce(&self, nonce_endpoint: Url) -> Result<String> {
        let NonceResponse { c_nonce } = self
            .client
            .post(nonce_endpoint)
            .send()
            .await?
            .json::<NonceResponse>()
            .await?;

        Ok(c_nonce)
    }

    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata,
        token_response: &TokenResponse,
        nonce: Option<String>,
        credential_configuration_id: String,
        credential_configuration: &CredentialConfigurationsSupportedObject,
        with_anonymous_access: bool,
    ) -> Result<CredentialResponse> {
        let signing_algorithm = self.select_signing_algorithm(credential_configuration)?;
        let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;
        let mut proof_builder = Proof::builder()
            .proof_type(ProofType::Jwt)
            .algorithm(signing_algorithm)
            .signer(self.subject.clone());

        if !with_anonymous_access {
            proof_builder = proof_builder.iss(
                self.subject
                    .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                    .await?,
            );
        }

        proof_builder = proof_builder
            .aud(credential_issuer_metadata.credential_issuer)
            .iat(chrono::Utc::now().timestamp());

        if let Some(nonce) = nonce {
            proof_builder = proof_builder.nonce(nonce);
        }

        // TODO: Update ProofBuilder to produce Proofs instead of Proof.
        let single_proof_object = Some(
            proof_builder
                .subject_syntax_type(subject_syntax_type.to_string())
                .build()
                .await?,
        );

        let jwt_string = match single_proof_object {
            Some(Proof::Jwt { jwt, .. }) => jwt,
            _ => return Err(anyhow::anyhow!("No JWT found in proof object")),
        };

        let proofs = Some(Proofs { jwt: vec![jwt_string] });

        let credential_request = CredentialRequest {
            credential_identifier_or_credential_configuration_id:
                CredentialIdentifierOrCredentialConfigurationId::CredentialConfigurationId(credential_configuration_id),
            proofs,
        };

        self.client
            .post(credential_issuer_metadata.credential_endpoint)
            .bearer_auth(token_response.access_token.clone())
            .json(&credential_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }

    pub async fn send_notification_request(
        &self,
        notification_endpoint: Url,
        notification_id: String,
        access_token: String,
        event: NotificationEvent,
        event_description: Option<String>,
    ) -> Result<()> {
        let notification_request = NotificationRequest {
            notification_id,
            event,
            event_description,
        };
        let response = self
            .client
            .post(notification_endpoint)
            .bearer_auth(access_token)
            .json(&notification_request)
            .send()
            .await?;

        if response.status() == 204 {
            Ok(())
        } else {
            Err(anyhow!("Failed to send notification: {}", response.status()))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::proof::KeyProofMetadata;
    use oid4vc_core::test_utils::TestSubject;
    use std::{collections::HashMap, sync::Arc};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[test]
    fn select_signing_algorithm_returns_first_supported_signing_algorithm_when_no_proof_types_supported() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let signing_algorithm = wallet
            // The Credential Issuer does not supply the `proof_types_supported` parameter, so the Wallet will use its own
            // preferred signing algorithm
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject::default())
            .unwrap();

        assert_eq!(signing_algorithm, Algorithm::EdDSA);
    }

    #[test]
    fn select_signing_algorithm_returns_error_when_it_cannot_find_matching_signing_algorithm() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let error = wallet
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject {
                proof_types_supported: HashMap::from_iter(vec![(
                    ProofType::Jwt,
                    KeyProofMetadata {
                        // This proof signing algorithm will not match any of the Wallet's supported signing algorithms.
                        proof_signing_alg_values_supported: vec![AlgIdentifier::String("RS256".to_string())],
                    },
                )]),
                ..Default::default()
            })
            .unwrap_err()
            .to_string();

        assert_eq!(error, "No matching supported signing algorithms found.");
    }

    #[test]
    fn select_signing_algorithm_returns_matching_signing_algorithm() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let signing_algorithm = wallet
            .select_signing_algorithm(&CredentialConfigurationsSupportedObject {
                proof_types_supported: HashMap::from_iter(vec![(
                    // This Proof Type is supported by the Wallet
                    ProofType::Jwt,
                    KeyProofMetadata {
                        // This proof signing algorithm will match the Wallet's supported signing algorithms.
                        proof_signing_alg_values_supported: vec![AlgIdentifier::String("EdDSA".to_string())],
                    },
                )]),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(signing_algorithm, Algorithm::EdDSA);
    }

    #[tokio::test]
    async fn wallet_successfully_retrieves_authorization_server_metadata() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/some/path"))
            .respond_with(ResponseTemplate::new(200).set_body_json(AuthorizationServerMetadata::default()))
            .mount(&mock_server)
            .await;

        // Assert that the Wallet can get the Authorization Server Metadata from the Credential Issuer URL with or without a trailing slash.
        let credential_issuer_url = format!("{}/some/path/", mock_server.uri()).parse().unwrap();
        assert!(wallet
            .get_authorization_server_metadata(credential_issuer_url)
            .await
            .is_ok());

        let credential_issuer_url = format!("{}/some/path", mock_server.uri()).parse().unwrap();
        assert!(wallet
            .get_authorization_server_metadata(credential_issuer_url)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn wallet_successfully_retrieves_authorization_server_metadata_from_openid_configuration() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/some/path/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(AuthorizationServerMetadata::default()))
            .mount(&mock_server)
            .await;

        // Assert that the Wallet can get the Authorization Server Metadata from the Credential Issuer URL with or without a trailing slash.
        let credential_issuer_url = format!("{}/some/path/", mock_server.uri()).parse().unwrap();
        assert!(wallet
            .get_authorization_server_metadata(credential_issuer_url)
            .await
            .is_ok());

        let credential_issuer_url = format!("{}/some/path", mock_server.uri()).parse().unwrap();
        assert!(wallet
            .get_authorization_server_metadata(credential_issuer_url)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn wallet_successfully_retrieves_credential_issuer_metadata() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-credential-issuer/some/path"))
            .respond_with(ResponseTemplate::new(200).set_body_json(CredentialIssuerMetadata::default()))
            .mount(&mock_server)
            .await;

        // Assert that the Wallet can get the Credential Issuer Metadata from the Credential Issuer URL with or without a trailing slash.
        let credential_issuer_url = format!("{}/some/path/", mock_server.uri()).parse().unwrap();
        assert!(wallet
            .get_credential_issuer_metadata(credential_issuer_url)
            .await
            .is_ok());

        let credential_issuer_url = format!("{}/some/path", mock_server.uri()).parse().unwrap();
        assert!(wallet
            .get_credential_issuer_metadata(credential_issuer_url)
            .await
            .is_ok());
    }
}
