use crate::{serialize_unit_struct, CredentialFormat, Format};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
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

#[derive(Debug, Eq, PartialEq)]
pub struct OpenIDCredential;

serialize_unit_struct!("openid_credential", OpenIDCredential);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_definition::CredentialDefinition,
        credential_format_profiles::{iso_mdl::mso_mdoc::MsoMdoc, w3c_verifiable_credentials::jwt_vc_json::JwtVcJson},
    };
    use serde_json::json;

    #[test]
    fn test_authorization_details_serde_jwt_vc_json() {
        let jwt_vc_json = json!({
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

        let authorization_details_mso_mdoc: AuthorizationDetails<JwtVcJson> =
            serde_json::from_value(jwt_vc_json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            authorization_details_mso_mdoc,
            AuthorizationDetails {
                type_: OpenIDCredential,
                locations: None,
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: (
                        CredentialDefinition {
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: Some(json!({
                                "given_name": {},
                                "last_name": {},
                                "degree": {}
                            })),
                        },
                        None
                    )
                        .into()
                },
            },
        );

        // Assert that the `AuthorizationDetails` can be serialized back into the original json Value.
        assert_eq!(
            serde_json::to_value(authorization_details_mso_mdoc).unwrap(),
            jwt_vc_json
        );
    }

    #[test]
    fn test_authorization_details_serde_mso_mdoc() {
        let mso_mdoc = json!({
            "type": "openid_credential",
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
                "org.iso.18013.5.1": {
                    "given_name": {},
                    "family_name": {},
                    "birth_date": {}
                },
                "org.iso.18013.5.1.aamva": {
                    "organ_donor": {}
                }
            }
        });

        let authorization_details_mso_mdoc: AuthorizationDetails<MsoMdoc> =
            serde_json::from_value(mso_mdoc.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            authorization_details_mso_mdoc,
            AuthorizationDetails {
                type_: OpenIDCredential,
                locations: None,
                credential_format: CredentialFormat {
                    format: MsoMdoc,
                    parameters: (
                        "org.iso.18013.5.1.mDL".to_string(),
                        Some(json!({
                            "org.iso.18013.5.1": {
                                "given_name": {},
                                "family_name": {},
                                "birth_date": {}
                            },
                            "org.iso.18013.5.1.aamva": {
                                "organ_donor": {}
                            }
                        })),
                        None
                    )
                        .into()
                },
            },
        );

        // Assert that the `AuthorizationDetails` can be serialized back into the original json Value.
        assert_eq!(serde_json::to_value(authorization_details_mso_mdoc).unwrap(), mso_mdoc);
    }
}
