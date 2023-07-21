use crate::{serialize_unit_struct, CredentialFormat, Format};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationDetails<F>
where
    F: Format,
{
    #[serde(rename = "type")]
    type_: OpenidCredential,
    #[serde(flatten)]
    credential_format: CredentialFormat<F>,
}

#[derive(Debug)]
pub struct OpenidCredential;

serialize_unit_struct!("openid_credential", OpenidCredential);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{credential_definition::CredentialDefinition, JwtVcJson};
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

        let _authorization_details: AuthorizationDetails<JwtVcJson> = serde_json::from_value(json).unwrap();
        dbg!(&_authorization_details);
    }

    #[test]
    fn test_authorization_details() {
        let jwt_vc_json = CredentialFormat {
            format: JwtVcJson,
            parameters: CredentialDefinition {
                type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                credential_subject: None,
            }
            .into(),
        };

        let authorization_details = AuthorizationDetails {
            type_: OpenidCredential,
            credential_format: jwt_vc_json,
        };

        println!("{}", serde_json::to_string_pretty(&authorization_details).unwrap());
    }
}
