use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<serde_json::Value>,
}
