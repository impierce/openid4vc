use crate::credential_format_profiles::{
    CredentialConfiguration, CredentialFormatCollection, CredentialFormats, WithParameters,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Represents the `openid_credential` field of the `AuthorizationDetailsObject`.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub enum OpenidCredential {
    #[default]
    #[serde(rename = "openid_credential")]
    Type,
}

/// Represents an object of the `authorization_details` field of the `AuthorizationRequest` object in the Authorization Code Flow as
/// described in [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#name-request-issuance-of-a-certa)
// TODO: Add `credential_configuration_id` field.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AuthorizationDetailsObject<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub r#type: OpenidCredential,
    pub locations: Option<Vec<Url>>,
    #[serde(flatten)]
    pub credential_configuration_or_format: CredentialConfigurationOrFormat<CFC>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum CredentialConfigurationOrFormat<CFC = CredentialFormats>
where
    CFC: CredentialFormatCollection,
{
    CredentialConfigurationId {
        credential_configuration_id: String,
        #[serde(flatten)]
        parameters: Option<CredentialConfiguration>,
    },
    CredentialFormat(CFC),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{jwt_vc_json, CredentialSubject},
        Parameters,
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::{fs::File, path::Path};

    fn json_example<T>(path: &str) -> T
    where
        T: DeserializeOwned,
    {
        let file_path = Path::new(path);
        let file = File::open(file_path).expect("file does not exist");
        serde_json::from_reader::<_, T>(file).expect("could not parse json")
    }

    #[test]
    fn test_authorization_details_object_with_format() {
        let json_value = json!({
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
              "type": [
                "VerifiableCredential",
                "UniversityDegreeCredential"
              ]
            }
        });

        assert_eq!(
            AuthorizationDetailsObject::<CredentialFormats<WithParameters>> {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialFormat(
                    CredentialFormats::JwtVcJson(Parameters {
                        parameters: (
                            jwt_vc_json::CredentialDefinition {
                                type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                                credential_subject: CredentialSubject::default(),
                            },
                            None,
                        )
                            .into(),
                    }),
                ),
            },
            serde_json::from_value(json_value).unwrap()
        );
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/80b2214814106e55e5fd09af3415ba4fc124b6be/examples.

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegreeCredential".to_string(),
                    parameters: Some(CredentialConfiguration::W3cVerifiableCredential(CredentialSubject {
                        credential_subject: Some(json!({
                            "given_name": {},
                            "family_name": {},
                            "degree": {}
                        })),
                    })),
                }
            }],
            json_example::<Vec<AuthorizationDetailsObject>>("tests/examples/authorization_details_jwt_vc_json.json")
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegree_LDP_VC".to_string(),
                    parameters: Some(CredentialConfiguration::W3cVerifiableCredential(CredentialSubject {
                        credential_subject: Some(json!({
                            "given_name": {},
                            "family_name": {},
                            "degree": {}
                        })),
                    })),
                }
            }],
            json_example::<Vec<AuthorizationDetailsObject>>("tests/examples/authorization_details_ldp_vc.json")
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "org.iso.18013.5.1.mDL".to_string(),
                    parameters: Some(CredentialConfiguration::MsoMdoc(Some(json!({
                        "org.iso.18013.5.1": {
                            "given_name": {},
                            "family_name": {},
                            "birth_date": {}
                        },
                        "org.iso.18013.5.1.aamva": {
                            "organ_donor": {}
                        }
                    })))),
                }
            }],
            json_example::<Vec<AuthorizationDetailsObject>>("tests/examples/authorization_details_mso_mdoc.json")
        );

        assert_eq!(
            vec![
                AuthorizationDetailsObject {
                    r#type: OpenidCredential::Type,
                    locations: None,
                    credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                        credential_configuration_id: "UniversityDegreeCredential".to_string(),
                        parameters: None,
                    }
                },
                AuthorizationDetailsObject {
                    r#type: OpenidCredential::Type,
                    locations: None,
                    credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                        credential_configuration_id: "org.iso.18013.5.1.mDL".to_string(),
                        parameters: None,
                    }
                }
            ],
            json_example::<Vec<AuthorizationDetailsObject>>(
                "tests/examples/authorization_details_multiple_credentials.json"
            )
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: Some(vec!["https://credential-issuer.example.com".parse().unwrap()]),
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegreeCredential".to_string(),
                    parameters: None,
                }
            }],
            json_example::<Vec<AuthorizationDetailsObject>>("tests/examples/authorization_details_with_as.json")
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegreeCredential".to_string(),
                    parameters: None,
                },
            }],
            json_example::<Vec<AuthorizationDetailsObject>>("tests/examples/authorization_details.json")
        );
    }
}
