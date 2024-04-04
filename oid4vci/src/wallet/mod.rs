use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::AuthorizationRequest;
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::CredentialOfferParameters;
use crate::credential_request::{BatchCredentialRequest, CredentialRequest};
use crate::credential_response::BatchCredentialResponse;
use crate::proof::{KeyProofType, ProofType};
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::Result;
use oid4vc_core::authentication::subject::SigningSubject;
use reqwest::Url;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::de::DeserializeOwned;

pub struct Wallet<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub subject: SigningSubject,
    pub default_subject_syntax_type: String,
    pub client: ClientWithMiddleware,
    phantom: std::marker::PhantomData<CFC>,
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> Wallet<CFC> {
    pub fn new(subject: SigningSubject, default_subject_syntax_type: String) -> Self {
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
        let client = ClientBuilder::new(reqwest::Client::new())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();
        Self {
            subject,
            default_subject_syntax_type,
            client,
            phantom: std::marker::PhantomData,
        }
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
                client_id: self.subject.identifier(&self.default_subject_syntax_type)?,
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

    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata<CFC>,
        token_response: &TokenResponse,
        credential_format: CFC,
    ) -> Result<CredentialResponse> {
        let credential_request = CredentialRequest {
            credential_format,
            proof: Some(
                KeyProofType::builder()
                    .proof_type(ProofType::Jwt)
                    .signer(self.subject.clone())
                    .iss(self.subject.identifier(&self.default_subject_syntax_type)?)
                    .aud(credential_issuer_metadata.credential_issuer)
                    .iat(1571324800)
                    .exp(9999999999i64)
                    // TODO: so is this REQUIRED or OPTIONAL?
                    .nonce(
                        token_response
                            .c_nonce
                            .as_ref()
                            .ok_or(anyhow::anyhow!("No c_nonce found."))?
                            .clone(),
                    )
                    .subject_syntax_type(&self.default_subject_syntax_type)
                    .build()?,
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
        credential_formats: Vec<CFC>,
    ) -> Result<BatchCredentialResponse> {
        let proof = Some(
            KeyProofType::builder()
                .proof_type(ProofType::Jwt)
                .signer(self.subject.clone())
                .iss(self.subject.identifier(&self.default_subject_syntax_type)?)
                .aud(credential_issuer_metadata.credential_issuer)
                .iat(1571324800)
                .exp(9999999999i64)
                // TODO: so is this REQUIRED or OPTIONAL?
                .nonce(
                    token_response
                        .c_nonce
                        .as_ref()
                        .ok_or(anyhow::anyhow!("No c_nonce found."))?
                        .clone(),
                )
                .subject_syntax_type(&self.default_subject_syntax_type)
                .build()?,
        );

        let batch_credential_request = BatchCredentialRequest {
            credential_requests: credential_formats
                .iter()
                .map(|credential_format| CredentialRequest {
                    credential_format: credential_format.to_owned(),
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
