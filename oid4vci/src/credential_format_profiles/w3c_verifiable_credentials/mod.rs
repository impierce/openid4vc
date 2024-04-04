use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

pub mod jwt_vc_json;
pub mod jwt_vc_json_ld;
pub mod ldp_vc;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct CredentialSubject {
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<serde_json::Value>,
}
