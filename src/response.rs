use serde::{Deserialize, Serialize};

/// Current implementation only supports the `id_token` response type and the cross-device implicit flow.
#[derive(Serialize, Deserialize, Debug)]
pub struct SiopResponse {
    pub id_token: String,
}

impl SiopResponse {
    pub fn new(id_token: String) -> Self {
        SiopResponse { id_token }
    }
}
