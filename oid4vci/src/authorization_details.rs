use crate::{
    credential_format_profiles::{CredentialFormat, Format},
    serialize_unit_struct,
};
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Represents the `authorization_details` field of the `AuthorizationRequest` object in the Authorization Code Flow as
/// described in [OpenID4VCI](https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-request-issuance-of-a-certa)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationDetails(pub Vec<AuthorizationDetailsJson>);

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationDetailsJson(serde_json::Value);

impl<F: Format> From<AuthorizationDetailsObject<F>> for AuthorizationDetailsJson {
    fn from(value: AuthorizationDetailsObject<F>) -> Self {
        AuthorizationDetailsJson(serde_json::to_value(value).unwrap())
    }
}

impl<'de, F: Format + DeserializeOwned> TryInto<AuthorizationDetailsObject<F>> for AuthorizationDetailsJson
where
    AuthorizationDetailsObject<F>: Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_into(self) -> Result<AuthorizationDetailsObject<F>, Self::Error> {
        serde_json::from_value(self.0)
    }
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct AuthorizationDetailsObject<F>
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
    use crate::credential_format_profiles::{
        iso_mdl::mso_mdoc::MsoMdoc,
        w3c_verifiable_credentials::{
            jwt_vc_json::{self, JwtVcJson},
            ldp_vc::{self, LdpVc},
        },
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::{fs::File, path::Path};

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    #[serde(untagged)]
    enum AuthorizationDetailsObjectEnum {
        JwtVcJson(AuthorizationDetailsObject<JwtVcJson>),
        LdpVc(AuthorizationDetailsObject<LdpVc>),
        MsoMdoc(AuthorizationDetailsObject<MsoMdoc>),
        Other(serde_json::Value),
    }

    impl From<AuthorizationDetails> for Vec<AuthorizationDetailsObjectEnum> {
        fn from(authorization_details: AuthorizationDetails) -> Self {
            authorization_details
                .0
                .into_iter()
                .map(|authorization_details_json| {
                    serde_json::from_value::<AuthorizationDetailsObjectEnum>(authorization_details_json.0.clone())
                        .unwrap()
                })
                .collect()
        }
    }

    fn json_example<T>(path: &str) -> T
    where
        T: DeserializeOwned,
    {
        let file_path = Path::new(path);
        let file = File::open(file_path).expect("file does not exist");
        serde_json::from_reader::<_, T>(file).expect("could not parse json")
    }

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

        let authorization_details_mso_mdoc: AuthorizationDetailsObject<JwtVcJson> =
            serde_json::from_value(jwt_vc_json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            authorization_details_mso_mdoc,
            AuthorizationDetailsObject {
                type_: OpenIDCredential,
                locations: None,
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
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

        // Assert that the `AuthorizationDetailsObject` can be serialized back into the original json Value.
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

        let authorization_details_mso_mdoc: AuthorizationDetailsObject<MsoMdoc> =
            serde_json::from_value(mso_mdoc.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            authorization_details_mso_mdoc,
            AuthorizationDetailsObject {
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

        // Assert that the `AuthorizationDetailsObject` can be serialized back into the original json Value.
        assert_eq!(serde_json::to_value(authorization_details_mso_mdoc).unwrap(), mso_mdoc);
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://bitbucket.org/openid/connect/src/master/openid-4-verifiable-credential-issuance/examples/.

        assert_eq!(
            vec![AuthorizationDetailsObjectEnum::JwtVcJson(AuthorizationDetailsObject {
                type_: OpenIDCredential,
                locations: None,
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: Some(json!({
                                "given_name": {},
                                "family_name": {},
                                "degree": {}
                            })),
                        },
                        None
                    )
                        .into()
                },
            })],
            Vec::<AuthorizationDetailsObjectEnum>::from(json_example::<AuthorizationDetails>(
                "tests/examples/authorization_details_jwt_vc_json.json"
            ))
        );

        assert_eq!(
            vec![AuthorizationDetailsObjectEnum::LdpVc(AuthorizationDetailsObject {
                type_: OpenIDCredential,
                locations: None,
                credential_format: CredentialFormat {
                    format: LdpVc,
                    parameters: (
                        ldp_vc::CredentialDefinition {
                            context: vec![
                                "https://www.w3.org/2018/credentials/v1".into(),
                                "https://www.w3.org/2018/credentials/examples/v1".into()
                            ],
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: Some(json!({
                                "given_name": {},
                                "family_name": {},
                                "degree": {}
                            })),
                        },
                        None
                    )
                        .into()
                },
            })],
            Vec::<AuthorizationDetailsObjectEnum>::from(json_example::<AuthorizationDetails>(
                "tests/examples/authorization_details_ldp_vc.json"
            ))
        );

        assert_eq!(
            vec![AuthorizationDetailsObjectEnum::MsoMdoc(AuthorizationDetailsObject {
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
            })],
            Vec::<AuthorizationDetailsObjectEnum>::from(json_example::<AuthorizationDetails>(
                "tests/examples/authorization_details_mso_mdoc.json"
            ))
        );

        assert_eq!(
            vec![
                AuthorizationDetailsObjectEnum::LdpVc(AuthorizationDetailsObject {
                    type_: OpenIDCredential,
                    locations: None,
                    credential_format: CredentialFormat {
                        format: LdpVc,
                        parameters: (
                            ldp_vc::CredentialDefinition {
                                context: vec![
                                    "https://www.w3.org/2018/credentials/v1".into(),
                                    "https://www.w3.org/2018/credentials/examples/v1".into()
                                ],
                                type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                                credential_subject: None,
                            },
                            None
                        )
                            .into()
                    },
                }),
                AuthorizationDetailsObjectEnum::MsoMdoc(AuthorizationDetailsObject {
                    type_: OpenIDCredential,
                    locations: None,
                    credential_format: CredentialFormat {
                        format: MsoMdoc,
                        parameters: ("org.iso.18013.5.1.mDL".to_string(), None, None).into()
                    },
                })
            ],
            Vec::<AuthorizationDetailsObjectEnum>::from(json_example::<AuthorizationDetails>(
                "tests/examples/authorization_details_multiple_credentials.json"
            ))
        );

        assert_eq!(
            vec![AuthorizationDetailsObjectEnum::JwtVcJson(AuthorizationDetailsObject {
                type_: OpenIDCredential,
                locations: Some(vec!["https://credential-issuer.example.com".parse().unwrap()]),
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: None,
                        },
                        None
                    )
                        .into()
                },
            })],
            Vec::<AuthorizationDetailsObjectEnum>::from(json_example::<AuthorizationDetails>(
                "tests/examples/authorization_details_with_as.json"
            ))
        );

        assert_eq!(
            vec![AuthorizationDetailsObjectEnum::JwtVcJson(AuthorizationDetailsObject {
                type_: OpenIDCredential,
                locations: None,
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: None,
                        },
                        None
                    )
                        .into()
                },
            })],
            Vec::<AuthorizationDetailsObjectEnum>::from(json_example::<AuthorizationDetails>(
                "tests/examples/authorization_details.json"
            ))
        );
    }
}
