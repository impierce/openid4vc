use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct SiopResponse {
    pub id_token: String,
}

impl SiopResponse {
    pub fn new(id_token: String) -> Self {
        SiopResponse { id_token }
    }
}
