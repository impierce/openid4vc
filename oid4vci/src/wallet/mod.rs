use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::AuthorizationRequest;
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use crate::credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject;
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::CredentialOfferParameters;
use crate::credential_request::{BatchCredentialRequest, CredentialRequest};
use crate::credential_response::BatchCredentialResponse;
use crate::proof::{KeyProofType, ProofType};
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::{anyhow, Result};
use jsonwebtoken::Algorithm;
use oid4vc_core::authentication::subject::SigningSubject;
use oid4vc_core::SubjectSyntaxType;
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::de::DeserializeOwned;
use std::str::FromStr;

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
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))
            .unwrap()
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

    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        authorization_details: Vec<AuthorizationDetailsObject<CFC>>,
    ) -> Result<AuthorizationResponse> {
        self.client
            .get(authorization_endpoint)
            // TODO: must be `form`, but `AuthorizationRequest needs to be able to serilalize properly.
            .json(&AuthorizationRequest {
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
                redirect_uri: None,
                scope: None,
                state: None,
                authorization_details,
            })
            .send()
            .await?
            .json::<AuthorizationResponse>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get authorization code"))
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

    fn select_signing_algorithm(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<Algorithm> {
        let credential_issuer_proof_signing_alg_values_supported = &credential_configuration
            .proof_types_supported
            .get(&ProofType::Jwt)
            .ok_or(anyhow::anyhow!(
                "`jwt` proof type is missing from the `proof_types_supported` parameter"
            ))?
            .proof_signing_alg_values_supported;

        self.proof_signing_alg_values_supported
            .iter()
            .find(|supported_algorithm| {
                credential_issuer_proof_signing_alg_values_supported.contains(supported_algorithm)
            })
            .cloned()
            .ok_or(anyhow::anyhow!("No supported signing algorithm found."))
    }

    fn select_subject_syntax_type(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<SubjectSyntaxType> {
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
            .cloned()
            .ok_or(anyhow::anyhow!("No supported subject syntax types found."))
    }

    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<CredentialResponse> {
        let credential_format = credential_configuration.credential_format.to_owned();

        let signing_algorithm = self.select_signing_algorithm(credential_configuration)?;
        let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;

        let credential_request = CredentialRequest {
            credential_format,
            proof: Some(
                KeyProofType::builder()
                    .proof_type(ProofType::Jwt)
                    .algorithm(signing_algorithm)
                    .signer(self.subject.clone())
                    .iss(
                        self.subject
                            .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                            .await?,
                    )
                    .aud(credential_issuer_metadata.credential_issuer)
                    // TODO: Use current time.
                    .iat(1571324800)
                    // TODO: so is this REQUIRED or OPTIONAL?
                    .nonce(
                        token_response
                            .c_nonce
                            .as_ref()
                            .ok_or(anyhow::anyhow!("No c_nonce found."))?
                            .clone(),
                    )
                    .subject_syntax_type(subject_syntax_type.to_string())
                    .build()
                    .await?,
            ),
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

    pub async fn get_batch_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_configurations: &[CredentialConfigurationsSupportedObject],
    ) -> Result<BatchCredentialResponse> {
        // TODO: This needs to be fixed since this current implementation assumes that for all credentials the same Proof Type is supported.
        let credential_configuration = credential_configurations
            .first()
            .ok_or(anyhow::anyhow!("No credential configurations found."))?;

        let signing_algorithm = self.select_signing_algorithm(credential_configuration)?;
        let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;

        let proof = Some(
            KeyProofType::builder()
                .proof_type(ProofType::Jwt)
                .algorithm(signing_algorithm)
                .signer(self.subject.clone())
                .iss(
                    self.subject
                        .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                        .await?,
                )
                .aud(credential_issuer_metadata.credential_issuer)
                // TODO: Use current time.
                .iat(1571324800)
                // TODO: so is this REQUIRED or OPTIONAL?
                .nonce(
                    token_response
                        .c_nonce
                        .as_ref()
                        .ok_or(anyhow::anyhow!("No c_nonce found."))?
                        .clone(),
                )
                .subject_syntax_type(subject_syntax_type.to_string())
                .build()
                .await?,
        );

        let batch_credential_request = BatchCredentialRequest {
            credential_requests: credential_configurations
                .iter()
                .map(|credential_configuration| CredentialRequest {
                    credential_format: credential_configuration.credential_format.to_owned(),
                    proof: proof.clone(),
                })
                .collect(),
        };

        self.client
            .post(credential_issuer_metadata.batch_credential_endpoint.unwrap())
            .bearer_auth(token_response.access_token.clone())
            .json(&batch_credential_request)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }
}
