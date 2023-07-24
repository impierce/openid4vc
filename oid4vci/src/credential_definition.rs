use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<serde_json::Value>,
}
