use getset::Getters;
use serde::{Deserialize, Serialize};

/// Current implementation only supports the `id_token` response type and the cross-device implicit flow.
#[derive(Serialize, Deserialize, Debug, Getters)]
pub struct SiopResponse {
    pub id_token: String,
    #[serde(skip_serializing)]
    #[getset(get = "pub")]
    redirect_uri: String,
}

impl SiopResponse {
    pub fn new(id_token: String, redirect_uri: String) -> Self {
        SiopResponse { redirect_uri, id_token }
    }
}
