use crate::{authorization_details::AuthorizationDetails, credential_format_profiles::Format};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// The Authorization Request is used to request authorization as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationRequest<F>
where
    F: Format,
{
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub authorization_details: AuthorizationDetails<F>,
}
