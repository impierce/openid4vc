use crate::authorization_details::AuthorizationDetails;
use crate::authorization_request::AuthorizationRequest;
use crate::authorization_response::AuthorizationResponse;
use crate::credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson;
use crate::credential_format_profiles::{CredentialFormat, Format};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_request::CredentialRequest;
use crate::proof::{Proof, ProofType};
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::Result;
use oid4vc_core::authentication::subject::SigningSubject;
use reqwest::Url;

pub struct Wallet {
    pub subject: SigningSubject,
    pub client: reqwest::Client,
}

impl Wallet {
    pub fn new(subject: SigningSubject) -> Self {
        Self {
            subject,
            client: reqwest::Client::new(),
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

    pub async fn get_credential_issuer_metadata(&self, credential_issuer_url: Url) -> Result<CredentialIssuerMetadata> {
        self.client
            .get(credential_issuer_url.join(".well-known/openid-credential-issuer")?)
            .send()
            .await?
            .json::<CredentialIssuerMetadata>()
            .await
            .map_err(|_| anyhow::anyhow!("Failed to get credential issuer metadata"))
    }

    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        authorization_details: AuthorizationDetails<JwtVcJson>,
    ) -> Result<AuthorizationResponse> {
        self.client
            .get(authorization_endpoint)
            // TODO: must be `form`, but `AuthorizationRequest needs to be able to serilalize properly.
            .json(&AuthorizationRequest::<JwtVcJson> {
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

    pub async fn get_credential<F: Format>(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata,
        token_response: &TokenResponse,
        credential_format: CredentialFormat<F>,
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
