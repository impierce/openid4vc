use crate::{serialize_unit_struct, CredentialFormat, Format};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationDetails<F>
where
    F: Format,
{
    #[serde(rename = "type")]
    pub type_: OpenIDCredential,
    pub locations: Option<Vec<Url>>,
    #[serde(flatten)]
    pub credential_format: CredentialFormat<F>,
}

#[derive(Debug)]
pub struct OpenIDCredential;

serialize_unit_struct!("openid_credential", OpenIDCredential);

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn test_deserialize() {
        let _json = json!({
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

        // let _authorization_details: AuthorizationDetails<JwtVcJson> = serde_json::from_value(json).unwrap();
        // dbg!(&_authorization_details);
    }

    #[test]
    fn test_authorization_details() {
        // let jwt_vc_json = CredentialFormat {
        //     format: JwtVcJson,
        //     parameters: CredentialDefinition {
        //         type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
        //         credential_subject: None,
        //     }
        //     .into(),
        // };

        // let authorization_details = AuthorizationDetails {
        //     type_: OpenIDCredential,
        //     locations: None,
        //     credential_format: jwt_vc_json,
        // };

        // println!("{}", serde_json::to_string_pretty(&authorization_details).unwrap());
    }
}
