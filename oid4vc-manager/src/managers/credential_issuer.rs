use crate::storage::Storage;
use anyhow::Result;
use oid4vc_core::{Subject, Subjects};
use oid4vci::{
    credential_format_profiles::{w3c_verifiable_credentials::jwt_vc_json::JwtVcJson, CredentialFormat},
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata, CredentialIssuer,
    },
    credential_offer::{CredentialOffer, CredentialOfferQuery, Grants},
};
use reqwest::Url;
use std::{net::TcpListener, sync::Arc};

#[derive(Clone)]
pub struct CredentialIssuerManager<S: Storage> {
    pub credential_issuer: CredentialIssuer,
    pub subjects: Arc<Subjects>,
    pub storage: S,
    pub listener: Arc<TcpListener>,
}

impl<S: Storage + Clone> CredentialIssuerManager<S> {
    pub fn new<const N: usize>(
        listener: Option<TcpListener>,
        storage: S,
        subjects: [Arc<dyn Subject>; N],
    ) -> Result<Self> {
        let listener = listener.unwrap_or_else(|| TcpListener::bind("127.0.0.1:0").unwrap());
        let issuer_url: Url = format!("http://{:?}", listener.local_addr()?).parse()?;
        Ok(Self {
            credential_issuer: CredentialIssuer {
                subject: subjects
                    .get(0)
                    .ok_or_else(|| anyhow::anyhow!("No subjects found."))?
                    .clone(),
                metadata: CredentialIssuerMetadata {
                    credential_issuer: issuer_url.clone(),
                    authorization_server: None,
                    credential_endpoint: format!("{issuer_url}credential").parse()?,
                    batch_credential_endpoint: None,
                    deferred_credential_endpoint: None,
                    credentials_supported: storage.get_credentials_supported(),
                    display: None,
                },
                authorization_server_metadata: AuthorizationServerMetadata {
                    issuer: issuer_url.clone(),
                    authorization_endpoint: format!("{issuer_url}authorize").parse()?,
                    token_endpoint: format!("{issuer_url}token").parse()?,
                    ..Default::default()
                },
            },
            subjects: Arc::new(Subjects::try_from(subjects)?),
            storage,
            listener: Arc::new(listener),
        })
    }

    pub fn credential_issuer_url(&self) -> Result<Url> {
        Ok(self.credential_issuer.metadata.credential_issuer.clone())
    }

    pub fn credential_offer_uri(&self) -> Result<String> {
        let credentials: CredentialFormat<JwtVcJson> = self
            .credential_issuer
            .metadata
            .credentials_supported
            .get(0)
            .ok_or_else(|| anyhow::anyhow!("No credentials supported."))?
            .clone()
            .try_into()?;
        Ok(CredentialOfferQuery::CredentialOffer(CredentialOffer {
            credential_issuer: self.credential_issuer.metadata.credential_issuer.clone(),
            credentials: vec![serde_json::to_value(credentials)?],
            grants: Some(Grants {
                authorization_code: self.storage.get_authorization_code(),
                pre_authorized_code: self.storage.get_pre_authorized_code(),
            }),
        })
        .to_string())
    }
}
