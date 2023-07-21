use crate::proof::{Cwt, Jwt, Proof, ProofType};
use crate::{
    authorization_server_metadata::AuthorizationServerMetadata,
    credential_definition::CredentialDefinition,
    credential_issuer_metadata::CredentialIssuerMetadata,
    credential_offer::Grants,
    credential_response::CredentialResponse,
    token_request::{GrantTypeIdentifier, TokenRequest},
    token_response::TokenResponse,
};
use crate::{credential_request::CredentialRequest, CredentialFormat, JwtVcJson, JwtVcJsonParameters};
use anyhow::Result;
use dif_presentation_exchange::ClaimFormatDesignation;
use reqwest::Url;

pub struct Wallet {
    pub client: reqwest::Client,
}

impl Wallet {
    pub fn new() -> Self {
        Self {
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

    pub async fn get_credential(
        &self,
        credential_endpoint: Url,
        token_response: &TokenResponse,
    ) -> Result<CredentialResponse> {
        self.client
            .post(credential_endpoint)
            .bearer_auth(token_response.access_token.clone())
            .json(&CredentialRequest {
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: JwtVcJsonParameters {
                        credential_definition: CredentialDefinition {
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: None,
                        },
                    },
                },
                proof: Some(Proof::Jwt { proof_type: Jwt, jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM".to_string() }),

            })
            .send()
            .await?
            .json()
            .await
            .map_err(|e| e.into())
    }
}
