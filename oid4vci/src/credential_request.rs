use crate::{proofs::Proofs};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credential Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CredentialRequest {
    #[serde(flatten)]
    pub credential_identifier_or_credential_configuration_id: CredentialIdentifierOrCredentialConfigurationId,
    pub proofs: Option<Proofs>,
    // TODO: add `credential_response_encryption` field when support for JWE is added.
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CredentialIdentifierOrCredentialConfigurationId {
    CredentialIdentifier(String),
    CredentialConfigurationId(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_credential_request_with_credential_configuration_identifier() {
        let credential_request_json = json!({
            "credential_configuration_id": "org.iso.18013.5.1.mDL",
            "proofs": {
                "jwt": ["eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"]
            }
        });

        let credential_request: CredentialRequest = serde_json::from_value(credential_request_json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_request,
            CredentialRequest {
                credential_identifier_or_credential_configuration_id: CredentialIdentifierOrCredentialConfigurationId::CredentialConfigurationId("org.iso.18013.5.1.mDL".to_string()),
                proofs: Some(Proofs {
                    jwt: vec![
                        "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ".to_string()
                    ]
                }), 
            },
        );

        // Assert that the `CredentialRequest` can be serialized back into the original json Value.
        assert_eq!(
            serde_json::to_value(credential_request).unwrap(),
            credential_request_json
        );
    }

    #[test]
    fn test_credential_request_with_multiple_proofs() {
        let credential_request_json = json!({
            "credential_identifier": "CivilEngineeringDegree-2023",
            "proofs": {
            "jwt": [
                "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiblVXQW9BdjNYWml0aDhFN2kxOU9kYXhPTFlGT3dNLVoyRXVNMDJUaXJUNCIsInkiOiJIc2tIVThCalVpMVU5WHFpN1N3bWo4Z3dBS18weGtjRGpFV183MVNvc0VZIn19",
                "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ"
                ]
            }
        });

        let credential_request: CredentialRequest = serde_json::from_value(credential_request_json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_request,
            CredentialRequest {
                credential_identifier_or_credential_configuration_id: CredentialIdentifierOrCredentialConfigurationId::CredentialIdentifier("CivilEngineeringDegree-2023".to_string()),
                proofs: Some(Proofs {
                    jwt: vec![
                        "eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiblVXQW9BdjNYWml0aDhFN2kxOU9kYXhPTFlGT3dNLVoyRXVNMDJUaXJUNCIsInkiOiJIc2tIVThCalVpMVU5WHFpN1N3bWo4Z3dBS18weGtjRGpFV183MVNvc0VZIn19".to_string(),
                        "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ".to_string()
                    ]
                }),
            },
        );

        // Assert that the `CredentialRequest` can be serialized back into the original json Value.
        assert_eq!(
            serde_json::to_value(credential_request).unwrap(),
            credential_request_json
        );
    }
}
