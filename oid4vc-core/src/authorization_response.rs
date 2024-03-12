use crate::openid4vc_extension::{Extension, ResponseHandle};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// The [`AuthorizationResponse`] is a set of claims that are sent by a provider to a client. On top of some generic
/// claims, it also contains a set of claims specific to an [`Extension`].
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationResponse<E: Extension> {
    #[serde(skip)]
    pub redirect_uri: String,
    pub state: Option<String>,
    #[serde(flatten)]
    pub extension: <E::ResponseHandle as ResponseHandle>::Parameters,
}
