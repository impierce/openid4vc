use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::AuthorizationRequest;
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, Format};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_request::CredentialRequest;
use crate::proof::{Proof, ProofType};
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::Result;
use oid4vc_core::authentication::subject::SigningSubject;
use reqwest::Url;
use serde::de::DeserializeOwned;

pub struct Wallet<CFC = CredentialFormats>
where
    CFC: CredentialFormatCollection + DeserializeOwned,
{
    pub subject: SigningSubject,
    pub client: reqwest::Client,
    phantom: std::marker::PhantomData<CFC>,
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> Wallet<CFC> {
    pub fn new(subject: SigningSubject) -> Self {
        Self {
            subject,
            client: reqwest::Client::new(),
            phantom: std::marker::PhantomData,
        }
    }

    pub async fn get_authorization_server_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata> {
        self.client
            .get(credential_issuer_url.join(".well-known/oauth-authorization-server")?)
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
        self.client
            .get(credential_issuer_url.join(".well-known/openid-credential-issuer")?)
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
                client_id: self.subject.identifier()?,
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
                Proof::builder()
                    .proof_type(ProofType::Jwt)
                    .signer(self.subject.clone())
                    .iss(self.subject.identifier()?)
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
}
