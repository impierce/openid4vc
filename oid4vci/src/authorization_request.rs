use crate::authorization_details::AuthorizationDetailsObject;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// The Authorization Request is used to request authorization as described here: openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#name-authorization-request
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<Url>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub authorization_details: Vec<AuthorizationDetailsObject>,
    pub issuer_state: Option<String>,
    // PKCE parameters
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Eq, PartialEq)]
pub enum CodeChallengeMethod {
    S256,
    #[default]
    #[serde(rename = "plain")]
    Plain,
}
