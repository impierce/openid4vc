use crate::storage::Storage;
use anyhow::Result;
use oid4vc_core::Subject;
use oid4vci::{
    credential_format_profiles::CredentialFormatCollection,
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata, CredentialIssuer,
    },
    credential_offer::{CredentialOffer, CredentialOfferParameters, Grants},
};
use reqwest::Url;
use std::{net::TcpListener, sync::Arc};

#[derive(Clone)]
pub struct CredentialIssuerManager<S: Storage<CFC>, CFC: CredentialFormatCollection> {
    pub credential_issuer: CredentialIssuer<CFC>,
    pub subject: Arc<dyn Subject>,
    pub storage: S,
    pub listener: Arc<TcpListener>,
}

impl<S: Storage<CFC>, CFC: CredentialFormatCollection> CredentialIssuerManager<S, CFC> {
    pub fn new(listener: Option<TcpListener>, storage: S, subject: Arc<dyn Subject>) -> Result<Self> {
        // `TcpListener::bind("127.0.0.1:0")` will bind to a random port.
        let listener = listener.unwrap_or_else(|| TcpListener::bind("127.0.0.1:0").unwrap());
        let issuer_url: Url = format!("http://{:?}", listener.local_addr()?).parse()?;
        Ok(Self {
            credential_issuer: CredentialIssuer {
                subject: subject.clone(),
                metadata: CredentialIssuerMetadata {
                    credential_issuer: issuer_url.clone(),
                    authorization_servers: vec![],
                    credential_endpoint: issuer_url.join("/credential")?,
                    batch_credential_endpoint: Some(issuer_url.join("/batch_credential")?),
                    deferred_credential_endpoint: None,
                    notification_endpoint: None,
                    credential_response_encryption: None,
                    credential_identifiers_supported: None,
                    signed_metadata: None,
                    display: None,
                    credential_configurations_supported: storage.get_credential_configurations_supported(),
                },
                authorization_server_metadata: AuthorizationServerMetadata {
                    issuer: issuer_url.clone(),
                    authorization_endpoint: Some(issuer_url.join("/authorize")?),
                    token_endpoint: Some(issuer_url.join("/token")?),
                    pre_authorized_grant_anonymous_access_supported: Some(true),
                    ..Default::default()
                },
            },
            subject,
            storage,
            listener: Arc::new(listener),
        })
    }

    pub fn credential_issuer_url(&self) -> Result<Url> {
        Ok(self.credential_issuer.metadata.credential_issuer.clone())
    }

    pub fn credential_offer(&self) -> Result<CredentialOfferParameters> {
        let credential_configuration_ids: Vec<String> = self
            .credential_issuer
            .metadata
            .credential_configurations_supported
            .iter()
            .map(|credential| credential.0.clone())
            .collect();
        Ok(CredentialOfferParameters {
            credential_issuer: self.credential_issuer.metadata.credential_issuer.clone(),
            credential_configuration_ids,
            grants: Some(Grants {
                authorization_code: self.storage.get_authorization_code(),
                pre_authorized_code: self.storage.get_pre_authorized_code(),
            }),
        })
    }

    pub fn credential_offer_uri(&self) -> Result<Url> {
        let issuer_url = self.credential_issuer.metadata.credential_issuer.clone();
        Ok(issuer_url.join("/credential_offer")?)
    }

    pub fn credential_offer_query(&self, by_reference: bool) -> Result<String> {
        if by_reference {
            Ok(CredentialOffer::CredentialOfferUri(self.credential_offer_uri()?).to_string())
        } else {
            Ok(CredentialOffer::CredentialOffer(Box::new(self.credential_offer()?)).to_string())
        }
    }
}
