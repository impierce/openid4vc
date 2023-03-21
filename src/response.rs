use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct SiopResponse {
    id_token: String,
}

impl SiopResponse {
    pub fn new(id_token: String) -> Self {
        SiopResponse { id_token }
    }
}
