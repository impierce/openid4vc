use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credential Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-credential-response.
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize, Clone)]
pub struct CredentialResponse {
    #[serde(flatten)]
    pub credential: CredentialResponseType,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

/// Batch Credential Response as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-batch-credential-response.
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct BatchCredentialResponse {
    pub credential_responses: Vec<CredentialResponseType>,
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

    #[test]
    fn test_batch_credential_response() {
        let batch_credential_response = BatchCredentialResponse {
            credential_responses: vec![
                CredentialResponseType::Deferred {
                    transaction_id: "123".to_string(),
                },
                CredentialResponseType::Immediate {
                    credential: json!({
                        "id": "http://example.edu/credentials/3732",
                        "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                        "issuer": "https://example.edu/issuers/14",
                        "issuanceDate": "2010-01-01T19:23:24Z",
                        "credentialSubject": {
                            "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                            "degree": {
                                "type": "BachelorDegree",
                                "name": "Bachelor of Science and Arts"
                            }
                        }
                    }),
                    notification_id: None,
                },
            ],
            c_nonce: Some("456".to_string()),
            c_nonce_expires_in: Some(789),
        };
        let serialized = serde_json::to_value(&batch_credential_response).unwrap();
        assert_eq!(
            serialized,
            json!({
                "credential_responses": [
                    {
                        "transaction_id": "123"
                    },
                    {
                        "credential": {
                            "id": "http://example.edu/credentials/3732",
                            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
                            "issuer": "https://example.edu/issuers/14",
                            "issuanceDate": "2010-01-01T19:23:24Z",
                            "credentialSubject": {
                                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                                "degree": {
                                    "type": "BachelorDegree",
                                    "name": "Bachelor of Science and Arts"
                                }
                            }
                        }
                    }
                ],
                "c_nonce": "456",
                "c_nonce_expires_in": 789
            })
        );
        let deserialized: BatchCredentialResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized, batch_credential_response);
    }
}
