use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::AuthorizationRequest;
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use crate::credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject;
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::CredentialOfferParameters;
use crate::credential_request::{CredentialIdentifierOrCredentialConfigurationId, CredentialRequest};
use crate::nonce_response::NonceResponse;
use crate::notification_request::{NotificationEvent, NotificationRequest};
use crate::proof::ProofType;
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
use serde::de::DeserializeOwned;
use serde::Serializer;
use serde_json::json;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug)]
pub struct Wallet<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub subject: SigningSubject,
    pub supported_subject_syntax_types: Vec<SubjectSyntaxType>,
    pub client: ClientWithMiddleware,
    pub proof_signing_alg_values_supported: Vec<Algorithm>,
    phantom: std::marker::PhantomData<CFC>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

// FIXME: Only PAR?
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct AuthorizationRequestByReference {
    pub client_id: String,
    pub request_uri: String,
}

pub fn uuid_as_urn<S>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&uuid.urn().to_string())
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> Wallet<CFC> {
    pub fn new(
        subject: SigningSubject,
        supported_subject_syntax_types: Vec<impl TryInto<SubjectSyntaxType>>,
        proof_signing_alg_values_supported: Vec<Algorithm>,
    ) -> anyhow::Result<Self> {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
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
            phantom: std::marker::PhantomData,
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

        // TODO(NGDIL): remove this NGDIL specific code. This is a temporary fix to get the authorization server metadata.
        oauth_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .pop_if_empty()
            .push(".well-known")
            .push("oauth-authorization-server");

        self.client
            .get(oauth_authorization_server_endpoint)
            .send()
            .await?
            .json::<AuthorizationServerMetadata>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get authorization server metadata"))
    }

    pub async fn get_credential_issuer_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<CredentialIssuerMetadata<CFC>> {
        let mut openid_credential_issuer_endpoint = credential_issuer_url.clone();

        // TODO(NGDIL): remove this NGDIL specific code. This is a temporary fix to get the credential issuer metadata.
        openid_credential_issuer_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .pop_if_empty()
            .push(".well-known")
            .push("openid-credential-issuer");

        self.client
            .get(openid_credential_issuer_endpoint)
            .send()
            .await?
            .json::<CredentialIssuerMetadata<CFC>>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential issuer metadata"))
    }

    // TODO: refactor to reduce the number of arguments
    #[allow(clippy::too_many_arguments)]
    pub async fn get_pushed_authorization_response(
        &self,
        pushed_authorization_request_endpoint: Url,
        redirect_uri: Url,
        state: String,
        authorization_details: Vec<AuthorizationDetailsObject<CFC>>,
        issuer_state: String,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<PushedAuthorizationResponse> {
        let authorization_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: self
                .subject
                .identifier(
                    &self
                        .supported_subject_syntax_types
                        .first()
                        .map(ToString::to_string)
                        .ok_or(anyhow!("No supported subject syntax types found."))?,
                    self.proof_signing_alg_values_supported[0],
                )
                .await?,
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
            .map_err(|_| anyhow::anyhow!("Failed to send pushed authorization request"))
    }

    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        authorization_details: Vec<AuthorizationDetailsObject<CFC>>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
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

        // FIXME: clean this mess up
        if let Some(pushed_response) = pushed_authorization_response {
            let authorization_request = json!({
                "client_id": client_id,
                "request_uri": pushed_response.request_uri.to_string(),
            });

            return Ok(self
                .client
                .get(authorization_endpoint)
                // TODO: implement method to convert AuthorizationRequest to form parameters
                .form(&authorization_request)
                .send()
                .await?
                .json::<AuthorizationResponse>()
                .await
                .unwrap());
            // .map_err(|_| anyhow::anyhow!("Failed to get authorization code"));
        }

        // FIXME: implement URL form encoding for AuthorizationRequest
        let authorization_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id,
            redirect_uri: None,
            scope: None,
            state: None,
            authorization_details,
            // FIXME
            issuer_state: None,
            code_challenge,
            code_challenge_method,
        };

        self.client
            .get(authorization_endpoint)
            // TODO: implement method to convert AuthorizationRequest to form parameters
            .form(&authorization_request)
            .send()
            .await?
            .json::<AuthorizationResponse>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get authorization code"))
    }

    pub async fn get_access_token(&self, token_endpoint: Url, token_request: TokenRequest) -> Result<TokenResponse> {
        let temp = self
            .client
            .post(token_endpoint)
            .form(&token_request)
            .send()
            .await
            .inspect(|response| {
                if !response.status().is_success() {
                    println!("Failed to get access token: {}", response.status());
                }
            })
            .inspect_err(|e| println!("Error getting access token: {}", e))?
            .json::<serde_json::Value>()
            .await
            .unwrap();

        println!("Token response: {}", serde_json::to_string_pretty(&temp).unwrap());

        // todo!();

        serde_json::from_value::<TokenResponse>(temp)
            .map_err(|_| anyhow::anyhow!("Failed to deserialize token response"))
    }

    // Select supported signing algorithm that matches the Credential Issuer's supported Proof Types.
    // Supplying the `proof` parameter to the Credential Request is only required when the `proof_types_supported`
    // parameter is present in the Credential Configuration in the Credential Issuer's metadata. However, if the
    // `proof_types_supported` is not present, the Wallet will still provide the `proof` signed with its own preferred
    // signing algorithm. For more information see: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-8.2-2.3.1
    fn select_signing_algorithm(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<Algorithm> {
        let proof_types_supported = &credential_configuration.proof_types_supported;

        // If the Credential Issuer does not define any supported Proof Types, then the Wallet wil uses its own default signing algorithm.
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
                credential_issuer_proof_signing_alg_values_supported.contains(supported_algorithm)
            })
            .cloned()
            .ok_or(anyhow::anyhow!("No matching supported signing algorithms found."))
    }

    // fn select_subject_syntax_type(
    //     &self,
    //     credential_configuration: &CredentialConfigurationsSupportedObject,
    // ) -> Result<SubjectSyntaxType> {
    //     let credential_issuer_cryptographic_binding_methods_supported: Vec<SubjectSyntaxType> =
    //         credential_configuration
    //             .cryptographic_binding_methods_supported
    //             .iter()
    //             .filter_map(|binding_method| SubjectSyntaxType::from_str(binding_method).ok())
    //             .collect();

    //     self.supported_subject_syntax_types
    //         .iter()
    //         .find(|supported_syntax_type| {
    //             credential_issuer_cryptographic_binding_methods_supported.contains(supported_syntax_type)
    //         })
    //         .cloned()
    //         .ok_or(anyhow::anyhow!("No supported subject syntax types found."))
    // }

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
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        nonce: Option<String>,
        credential_configuration_id: String,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<CredentialResponse> {
        let signing_algorithm = self.select_signing_algorithm(credential_configuration)?;
        // let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;

        let subject_syntax_type =
            SubjectSyntaxType::from_str("did:jwk").map_err(|_| anyhow::anyhow!("Invalid subject syntax type"))?;

        let mut proof_builder = Proof::builder()
            .proof_type(ProofType::Jwt)
            .algorithm(signing_algorithm)
            .signer(self.subject.clone())
            .iss(
                self.subject
                    .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                    .await?,
            )
            .aud(credential_issuer_metadata.credential_issuer)
            .iat(chrono::Utc::now().timestamp());

        if let Some(nonce) = nonce {
            proof_builder = proof_builder.nonce(nonce);
        }

        let proof = Some(
            proof_builder
                .subject_syntax_type(subject_syntax_type.to_string())
                .build()
                .await?,
        );

        let credential_request = CredentialRequest {
            credential_identifier_or_credential_configuration_id:
                CredentialIdentifierOrCredentialConfigurationId::CredentialConfigurationId(credential_configuration_id),
            proof,
            proofs: None,
        };

        println!(
            "Credential request: {}",
            serde_json::to_string_pretty(&credential_request).unwrap()
        );

        let temp = self
            .client
            .post(credential_issuer_metadata.credential_endpoint)
            .bearer_auth(token_response.access_token.clone())
            .json(&credential_request)
            .send()
            .await
            .inspect(|response| {
                if !response.status().is_success() {
                    println!("Failed to get credential: {}", response.status());
                }
            })?
            .json::<serde_json::Value>()
            .await
            .unwrap();

        println!("Credential response: {}", serde_json::to_string_pretty(&temp).unwrap());

        serde_json::from_value::<CredentialResponse>(temp)
            .map_err(|_| anyhow::anyhow!("Failed to deserialize credential response"))
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
                        proof_signing_alg_values_supported: vec![Algorithm::RS256],
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
                        proof_signing_alg_values_supported: vec![Algorithm::EdDSA],
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
            .and(path("/some/path/.well-known/oauth-authorization-server"))
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
            .and(path("/some/path/.well-known/openid-credential-issuer"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(CredentialIssuerMetadata::<CredentialFormats>::default()),
            )
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
