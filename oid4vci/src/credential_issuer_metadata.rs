use dif_presentation_exchange::ClaimFormatDesignation;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialIssuerMetadata {
    credential_issuer: Url,
    authorization_server: Option<Url>,
    credential_endpoint: Option<Url>,
    batch_credential_endpoint: Option<Url>,
    deferred_credential_endpoint: Option<Url>,
    credentials_supported: Vec<CredentialsSupportedObject>,
    // TODO: @damader wdyt?
    display: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialsSupportedObject {
    format: ClaimFormatDesignation,
    // A JSON string identifying the respective object. The value MUST be unique across all credentials_supported
    // entries in the Credential Issuer Metadata.
    id: Option<String>,
    cryptographic_binding_methods_supported: Option<Vec<String>>,
    cryptographic_suites_supported: Option<Vec<String>>,
    proof_types_supported: Option<Vec<String>>,
    // TODO: fix this
    display: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialsSupportedObjectDisplay {
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
