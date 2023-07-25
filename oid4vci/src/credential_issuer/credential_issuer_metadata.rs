use super::credentials_supported::CredentialsSupportedObject;
use crate::credential_format_profiles::CredentialFormatCollection;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Credential Issuer Metadata as described here:
/// https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialIssuerMetadata<CFC>
where
    CFC: CredentialFormatCollection,
{
    pub credential_issuer: Url,
    pub authorization_server: Option<Url>,
    pub credential_endpoint: Url,
    pub batch_credential_endpoint: Option<Url>,
    pub deferred_credential_endpoint: Option<Url>,
    pub credentials_supported: Vec<CredentialsSupportedObject<CFC>>,
    pub display: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialsSupportedDisplay {
    name: String,
    locale: Option<String>,
    logo: Option<Logo>,
    description: Option<String>,
    background_color: Option<String>,
    text_color: Option<String>,
    #[serde(flatten)]
    other: Option<Map<String, Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Logo {
    url: Option<Url>,
    alt_text: Option<String>,
    #[serde(flatten)]
    other: Option<Map<String, Value>>,
}
