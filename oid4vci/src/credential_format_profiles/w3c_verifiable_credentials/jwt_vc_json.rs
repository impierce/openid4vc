use crate::credential_format;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

credential_format!("jwt_vc_json", JwtVcJson, {
    credential_definition: CredentialDefinition
});

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub type_: Vec<String>,
}
