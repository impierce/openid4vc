use getset::Getters;
use serde::{Deserialize, Serialize};

/// Current implementation only supports the `id_token` response type and the cross-device implicit flow.
#[derive(Serialize, Deserialize, Debug, Getters)]
pub struct SiopResponse {
    #[serde(skip)]
    #[getset(get = "pub")]
    redirect_uri: String,
    pub id_token: String,
}

impl SiopResponse {
    pub fn new(redirect_uri: String, id_token: String) -> Self {
        SiopResponse { redirect_uri, id_token }
    }
}
