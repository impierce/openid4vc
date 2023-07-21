use std::sync::Arc;

use crate::proof::{Proof, ProofType};
use crate::Format;
use crate::{
    authorization_server_metadata::AuthorizationServerMetadata,
    credential_issuer_metadata::CredentialIssuerMetadata,
    credential_offer::Grants,
    credential_response::CredentialResponse,
    token_request::{GrantTypeIdentifier, TokenRequest},
    token_response::TokenResponse,
};
use crate::{credential_request::CredentialRequest, CredentialFormat, JwtVcJson};
use anyhow::Result;
use oid4vc_core::Subject;
use reqwest::Url;

pub type SigningSubject = Arc<dyn Subject>;

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

    pub async fn get_access_token(
        &self,
        token_endpoint: Url,
        grants: Grants,
        user_pin: Option<String>,
    ) -> Result<TokenResponse> {
        dbg!(grants.pre_authorized_code.clone().unwrap().pre_authorized_code);
        self.client
            .post(token_endpoint)
            .form(&TokenRequest {
                grant_type: GrantTypeIdentifier::PreAuthorizedCode,
                pre_authorized_code: grants.pre_authorized_code.unwrap().pre_authorized_code,
                user_pin,
            })
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
        let temp = CredentialRequest {
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
                    .nonce(token_response.c_nonce.clone().unwrap())
                    .build()?,
            ),
        };

        let temp2 = serde_json::to_string(&temp)?;
        let temp: CredentialRequest<JwtVcJson> = serde_json::from_str(&temp2)?;

        self.client
            .post(credential_issuer_metadata.credential_endpoint)
            .bearer_auth(token_response.access_token.clone())
            .json(&temp)
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }
}
