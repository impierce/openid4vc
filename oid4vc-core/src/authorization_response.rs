use crate::Extension;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Default, Deserialize, Debug, PartialEq)]
pub struct AuthorizationResponse<E: Extension> {
    #[serde(skip)]
    pub redirect_uri: String,
    pub state: Option<String>,
    #[serde(flatten)]
    pub extension: E::AuthorizationResponse,
}
