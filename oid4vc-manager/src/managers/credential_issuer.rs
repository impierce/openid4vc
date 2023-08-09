use crate::storage::Storage;
use anyhow::Result;
use oid4vc_core::{Subject, Subjects};
use oid4vci::{
    credential_format_profiles::CredentialFormatCollection,
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata, CredentialIssuer,
    },
    credential_offer::{CredentialOffer, CredentialOfferQuery, CredentialsObject, Grants},
};
use reqwest::Url;
use std::{net::TcpListener, sync::Arc};

#[derive(Clone)]
pub struct CredentialIssuerManager<S: Storage<CFC>, CFC: CredentialFormatCollection> {
    pub credential_issuer: CredentialIssuer<CFC>,
    pub subjects: Arc<Subjects>,
    pub storage: S,
    pub listener: Arc<TcpListener>,
}

impl<S: Storage<CFC> + Clone, CFC: CredentialFormatCollection> CredentialIssuerManager<S, CFC> {
    pub fn new<const N: usize>(
        listener: Option<TcpListener>,
        storage: S,
        subjects: [Arc<dyn Subject>; N],
    ) -> Result<Self> {
        // `TcpListener::bind("127.0.0.1:0")` will bind to a random port.
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
                    credential_endpoint: issuer_url.join("/credential")?,
                    batch_credential_endpoint: Some(issuer_url.join("/batch_credential")?),
                    deferred_credential_endpoint: None,
                    credentials_supported: storage.get_credentials_supported(),
                    display: None,
                },
                authorization_server_metadata: AuthorizationServerMetadata {
                    issuer: issuer_url.clone(),
                    authorization_endpoint: issuer_url.join("/authorize")?,
                    token_endpoint: issuer_url.join("/token")?,
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
        let credentials: Vec<_> = self
            .credential_issuer
            .metadata
            .credentials_supported
            .iter()
            .map(|credential| CredentialsObject::ByValue(credential.credential_format.clone()))
            .collect();
        Ok(CredentialOfferQuery::CredentialOffer(CredentialOffer {
            credential_issuer: self.credential_issuer.metadata.credential_issuer.clone(),
            credentials,
            grants: Some(Grants {
                authorization_code: self.storage.get_authorization_code(),
                pre_authorized_code: self.storage.get_pre_authorized_code(),
            }),
        })
        .to_string())
    }
}
