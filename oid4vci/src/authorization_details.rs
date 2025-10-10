use crate::{
    credential_format_profiles::{CredentialConfiguration, CredentialFormats, WithParameters},
    credential_issuer::credential_configurations_supported::ClaimDescription,
};
use oid4vc_core::claim_path_pointer::ClaimPathPointer;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// TODO: use `nutype`
/// Represents the `openid_credential` field of the `AuthorizationDetailsObject`.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Default, Clone)]
pub enum OpenidCredential {
    #[default]
    #[serde(rename = "openid_credential")]
    Type,
}

/// Represents an object of the `authorization_details` field of the `AuthorizationRequest` object in the Authorization Code Flow as
/// described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-using-authorization-details
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AuthorizationDetailsObject {
    pub r#type: OpenidCredential,
    pub locations: Option<Vec<Url>>,
    #[serde(flatten)]
    pub credential_configuration_or_format: CredentialConfigurationOrFormat,
    pub claims: Option<Vec<AuthorizationDetailsClaim>>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct AuthorizationDetailsClaim {
    pub path: ClaimPathPointer,
    #[serde(default)]
    pub mandatory: bool,
}

impl From<ClaimDescription> for AuthorizationDetailsClaim {
    fn from(claim: ClaimDescription) -> Self {
        Self {
            path: claim.path,
            mandatory: claim.mandatory,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum CredentialConfigurationOrFormat {
    CredentialConfigurationId {
        credential_configuration_id: String,
        #[serde(flatten)]
        parameters: Option<CredentialConfiguration>,
    },
    CredentialFormat(CredentialFormats<WithParameters>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{jwt_vc_json, CredentialSubject},
        Parameters,
    };
    use oid4vc_core::claim_path_pointer::ClaimPathElement;
    use serde_json::{from_str, json};

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
            AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialFormat(
                    CredentialFormats::JwtVcJson(Parameters {
                        parameters: (jwt_vc_json::CredentialDefinition {
                            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                            credential_subject: CredentialSubject::default(),
                        })
                        .into(),
                    }),
                ),
                claims: None,
            },
            serde_json::from_value(json_value).unwrap()
        );
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/80b2214814106e55e5fd09af3415ba4fc124b6be/examples

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegreeCredential".to_string(),
                    parameters: None,
                },
                claims: Some(vec![
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("credentialSubject".to_string()),
                            ClaimPathElement::String("given_name".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("credentialSubject".to_string()),
                            ClaimPathElement::String("family_name".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("credentialSubject".to_string()),
                            ClaimPathElement::String("degree".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    }
                ]),
            }],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!(
                "../tests/examples/authorization_details_jwt_vc_json.json"
            ))
            .unwrap()
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegree_LDP_VC".to_string(),
                    parameters: None,
                },
                claims: Some(vec![
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("credentialSubject".to_string()),
                            ClaimPathElement::String("given_name".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("credentialSubject".to_string()),
                            ClaimPathElement::String("family_name".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("credentialSubject".to_string()),
                            ClaimPathElement::String("degree".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    }
                ]),
            }],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!(
                "../tests/examples/authorization_details_ldp_vc.json"
            ))
            .unwrap()
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "org.iso.18013.5.1.mDL".to_string(),
                    parameters: None,
                },
                claims: Some(vec![
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                            ClaimPathElement::String("given_name".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                            ClaimPathElement::String("family_name".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                            ClaimPathElement::String("birth_date".to_string())
                        ])
                        .unwrap(),
                        mandatory: false,
                    },
                    AuthorizationDetailsClaim {
                        path: ClaimPathPointer::try_new(vec![
                            ClaimPathElement::String("org.iso.18013.5.1.aamva".to_string()),
                            ClaimPathElement::String("organ_donor".to_string()),
                        ])
                        .unwrap(),
                        mandatory: false,
                    }
                ]),
            }],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!(
                "../tests/examples/authorization_details_mso_mdoc.json"
            ))
            .unwrap()
        );

        assert_eq!(
            vec![
                AuthorizationDetailsObject {
                    r#type: OpenidCredential::Type,
                    locations: None,
                    credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                        credential_configuration_id: "UniversityDegreeCredential".to_string(),
                        parameters: None,
                    },
                    claims: None,
                },
                AuthorizationDetailsObject {
                    r#type: OpenidCredential::Type,
                    locations: None,
                    credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                        credential_configuration_id: "org.iso.18013.5.1.mDL".to_string(),
                        parameters: None,
                    },
                    claims: None,
                }
            ],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!(
                "../tests/examples/authorization_details_multiple_credentials.json"
            ))
            .unwrap()
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialFormat(
                    CredentialFormats::DcSdJwt(Parameters {
                        parameters: ("SD_JWT_VC_example_in_OpenID4VCI".to_string()).into(),
                    }),
                ),
                claims: None,
            }],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!(
                "../tests/examples/authorization_details_sd_jwt_vc.json"
            ))
            .unwrap()
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: Some(vec!["https://credential-issuer.example.com".parse().unwrap()]),
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegreeCredential".to_string(),
                    parameters: None,
                },
                claims: None,
            }],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!(
                "../tests/examples/authorization_details_with_as.json"
            ))
            .unwrap()
        );

        assert_eq!(
            vec![AuthorizationDetailsObject {
                r#type: OpenidCredential::Type,
                locations: None,
                credential_configuration_or_format: CredentialConfigurationOrFormat::CredentialConfigurationId {
                    credential_configuration_id: "UniversityDegreeCredential".to_string(),
                    parameters: None,
                },
                claims: None,
            }],
            from_str::<Vec<AuthorizationDetailsObject>>(include_str!("../tests/examples/authorization_details.json"))
                .unwrap()
        );
    }
}
