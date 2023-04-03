use getset::Getters;
use serde::Deserialize;

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    IdToken,
}

/// [`SiopRequest`] is a request from a [crate::relying_party::RelyingParty] (RP) to a [crate::provider::Provider] (SIOP).
#[allow(dead_code)]
#[derive(Deserialize, Debug, Getters)]
pub struct SiopRequest {
    response_type: ResponseType,
    response_mode: Option<String>,
    #[getset(get = "pub")]
    client_id: String,
    request_uri: Option<String>,
    scope: String,
    // MUST be present in cross-device SIOP request
    #[getset(get = "pub")]
    redirect_uri: Option<String>,
    #[getset(get = "pub")]
    nonce: String,
    #[getset(get = "pub")]
    subject_syntax_types_supported: Vec<String>,
}

impl SiopRequest {
    pub fn is_cross_device_request(&self) -> bool {
        self.response_mode == Some("post".to_owned())
    }
}
