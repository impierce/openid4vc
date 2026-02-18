use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credential Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
pub struct CredentialResponse {
    #[serde(flatten)]
    pub credential: CredentialResponseType,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
#[serde(untagged)]
pub enum CredentialResponseType {
    Deferred {
        transaction_id: String,
        interval: u64,
    },
    Immediate {
        credentials: Vec<CredentialResponseObject>,
        notification_id: Option<String>,
    },
}

#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
pub struct CredentialResponseObject {
    // TODO: This should be a more complex type
    pub credential: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_credential_response() {
        let credential_response = CredentialResponse {
            credential: CredentialResponseType::Deferred {
                transaction_id: "123".to_string(),
                interval: 5,
            },
        };
        let serialized = serde_json::to_value(&credential_response).unwrap();
        assert_eq!(
            serialized,
            json!({
                "transaction_id": "123",
                "interval": 5
            })
        );
        let deserialized: CredentialResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized, credential_response);
    }
}
