use dif_presentation_exchange::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenidCredential;

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizationDetails {
    #[serde(rename = "type")]
    type_: OpenidCredential,
    locations: Vec<String>,
    format: ClaimFormatDesignation,
    #[serde(flatten)]
    format_parameters: Option<serde_json::Map<String, serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deserialize() {
        let json = json!({
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "UniversityDegreeCredential"
                ],
                "credentialSubject": {
                    "given_name": {},
                    "last_name": {},
                    "degree": {}
                }
            }
        });

        let _authorization_details: AuthorizationDetails = serde_json::from_value(json).unwrap();
        dbg!(&_authorization_details);
    }
}
