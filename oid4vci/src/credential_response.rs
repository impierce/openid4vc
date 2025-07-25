use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credential Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-response
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
pub struct CredentialResponse {
    #[serde(flatten)]
    pub credential: CredentialResponseType,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
#[serde(untagged)]
pub enum CredentialResponseType {
    Deferred {
        transaction_id: String,
    },
    Immediate {
        credential: serde_json::Value,
        notification_id: Option<String>,
    },
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
            },
            c_nonce: Some("456".to_string()),
            c_nonce_expires_in: Some(789),
        };
        let serialized = serde_json::to_value(&credential_response).unwrap();
        assert_eq!(
            serialized,
            json!({
                "transaction_id": "123",
                "c_nonce": "456",
                "c_nonce_expires_in": 789
            })
        );
        let deserialized: CredentialResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized, credential_response);
    }
}
