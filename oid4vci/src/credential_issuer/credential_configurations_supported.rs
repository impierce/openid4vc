use std::collections::HashMap;

use crate::{
    credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters},
    proof::{KeyProofMetadata, ProofType},
};
use oid4vc_core::claim_path_pointer::ClaimPathPointer;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// Credentials Supported object as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-11.2.3-2.11.1
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct CredentialConfigurationsSupportedObject<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    /// This field is flattened into a `format` field and optionally extra format-specific fields.
    #[serde(flatten)]
    pub credential_format: CFC,
    // Use `Scope` from oid4vc-core/src/scope.rs.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptographic_binding_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub proof_types_supported: HashMap<ProofType, KeyProofMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub display: Vec<CredentialConfigurationsSupportedDisplay>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub claims: Vec<ClaimDescription>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ClaimDescription {
    pub path: ClaimPathPointer,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub display: Vec<ClaimDescriptionDisplay>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct ClaimDescriptionDisplay {
    pub name: String,
    pub locale: Option<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Logo {
    pub uri: Url,
    pub alt_text: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Image {
    pub uri: Url,
}

// TODO: implement builder pattern for this struct.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct CredentialConfigurationsSupportedDisplay {
    pub name: String,
    pub locale: Option<String>,
    pub logo: Option<Logo>,
    pub description: Option<String>,
    pub background_image: Option<Image>,
    // TODO: use `nutype` crate for color validation
    pub background_color: Option<String>,
    // TODO: use `nutype` crate for color validation
    pub text_color: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{jwt_vc_json, ldp_vc, CredentialSubject},
        CredentialFormats, Parameters,
    };
    use jsonwebtoken::Algorithm;
    use oid4vc_core::claim_path_pointer::ClaimPathElement;
    use serde_json::{from_str, json};
    use std::collections::HashMap;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestWrapper {
        credential_configurations_supported: HashMap<String, CredentialConfigurationsSupportedObject>,
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/80b2214814106e55e5fd09af3415ba4fc124b6be/examples

        assert_eq!(
            TestWrapper {
                credential_configurations_supported: vec![(
                    "UniversityDegreeCredential".to_string(),
                    CredentialConfigurationsSupportedObject {
                        credential_format: CredentialFormats::JwtVcJson(Parameters {
                            parameters: (jwt_vc_json::CredentialDefinition {
                                type_: vec![
                                    "VerifiableCredential".to_string(),
                                    "UniversityDegreeCredential".to_string()
                                ],
                                credential_subject: CredentialSubject {
                                    credential_subject: None
                                },
                            })
                            .into()
                        }),
                        scope: Some("UniversityDegree".to_string()),
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec!["ES256".to_string()],
                        proof_types_supported: vec![(
                            ProofType::Jwt,
                            KeyProofMetadata {
                                proof_signing_alg_values_supported: vec![Algorithm::ES256]
                            }
                        )]
                        .into_iter()
                        .collect(),
                        display: vec![serde_json::from_value(json!({
                            "name": "University Credential",
                            "locale": "en-US",
                            "logo": {
                                "uri": "https://university.example.edu/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        }))
                        .unwrap()],
                        claims: vec![
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![serde_json::from_value(json!({
                                    "name": "Given Name",
                                    "locale": "en-US"
                                }))
                                .unwrap()],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![serde_json::from_value(json!({
                                    "name": "Surname",
                                    "locale": "en-US"
                                }))
                                .unwrap()],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("degree".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("gpa".to_string())
                                ])
                                .unwrap(),
                                mandatory: true,
                                display: vec![serde_json::from_value(json!({
                                    "name": "GPA",
                                }))
                                .unwrap()],
                            }
                        ]
                    }
                )]
                .into_iter()
                .collect()
            },
            from_str::<TestWrapper>(include_str!(
                "../../tests/examples/credential_metadata_jwt_vc_json.json"
            ))
            .unwrap()
        );

        assert_eq!(
            TestWrapper {
                credential_configurations_supported: vec![(
                    "UniversityDegree_LDP_VC".to_string(),
                    CredentialConfigurationsSupportedObject {
                        credential_format: CredentialFormats::LdpVc(Parameters {
                            parameters: (ldp_vc::CredentialDefinition {
                                context: vec![
                                    "https://www.w3.org/2018/credentials/v1".to_string(),
                                    "https://www.w3.org/2018/credentials/examples/v1".to_string()
                                ],
                                type_: vec![
                                    "VerifiableCredential".to_string(),
                                    "UniversityDegreeCredential".to_string()
                                ],
                                credential_subject: CredentialSubject {
                                    credential_subject: None
                                },
                            })
                            .into()
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec!["Ed25519Signature2018".to_string()],
                        proof_types_supported: HashMap::new(),
                        display: vec![serde_json::from_value(json!({
                                "name": "University Credential",
                                "locale": "en-US",
                                "logo": {
                                    "uri": "https://university.example.edu/public/logo.png",
                                    "alt_text": "a square logo of a university"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }
                        ))
                        .unwrap()],
                        claims: vec![
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![serde_json::from_value(json!({
                                    "name": "Given Name",
                                    "locale": "en-US"
                                }))
                                .unwrap()],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![serde_json::from_value(json!({
                                    "name": "Surname",
                                    "locale": "en-US"
                                }))
                                .unwrap()],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("degree".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("credentialSubject".to_string()),
                                    ClaimPathElement::String("gpa".to_string())
                                ])
                                .unwrap(),
                                mandatory: true,
                                display: vec![serde_json::from_value(json!({
                                    "name": "GPA",
                                }))
                                .unwrap()],
                            }
                        ]
                    },
                )]
                .into_iter()
                .collect()
            },
            from_str::<TestWrapper>(include_str!("../../tests/examples/credential_metadata_ldp_vc.json")).unwrap()
        );

        assert_eq!(
            TestWrapper {
                credential_configurations_supported: vec![(
                    "org.iso.18013.5.1.mDL".to_string(),
                    CredentialConfigurationsSupportedObject {
                        credential_format: CredentialFormats::MsoMdoc(Parameters {
                            parameters: ("org.iso.18013.5.1.mDL".to_string()).into()
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: vec!["cose_key".to_string()],
                        credential_signing_alg_values_supported: vec![
                            "ES256".to_string(),
                            "ES384".to_string(),
                            "ES512".to_string()
                        ],
                        proof_types_supported: HashMap::new(),
                        display: vec![
                            serde_json::from_value(json!({
                                "name": "Mobile Driving License",
                                "locale": "en-US",
                                "logo": {
                                    "uri": "https://state.example.org/public/mdl.png",
                                    "alt_text": "state mobile driving license"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }))
                            .unwrap(),
                            serde_json::from_value(json!({
                                "name": "モバイル運転免許証",
                                "locale": "ja-JP",
                                "logo": {
                                    "uri": "https://state.example.org/public/mdl.png",
                                    "alt_text": "米国州発行のモバイル運転免許証"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }))
                            .unwrap()
                        ],
                        claims: vec![
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![
                                    serde_json::from_value(json!({
                                        "name": "Given Name",
                                        "locale": "en-US"
                                    }))
                                    .unwrap(),
                                    serde_json::from_value(json!({
                                        "name": "名前",
                                        "locale": "ja-JP"
                                    }))
                                    .unwrap()
                                ],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![serde_json::from_value(json!({
                                    "name": "Surname",
                                    "locale": "en-US"
                                }))
                                .unwrap()],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("birth_date".to_string())
                                ])
                                .unwrap(),
                                mandatory: true,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1.aamva".to_string()),
                                    ClaimPathElement::String("organ_donor".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            }
                        ]
                    }
                )]
                .into_iter()
                .collect()
            },
            from_str::<TestWrapper>(include_str!("../../tests/examples/credential_metadata_mso_mdoc.json")).unwrap()
        );

        assert_eq!(
            TestWrapper {
                credential_configurations_supported: vec![(
                    "SD_JWT_VC_example_in_OpenID4VCI".to_string(),
                    CredentialConfigurationsSupportedObject {
                        credential_format: CredentialFormats::DcSdJwt(Parameters {
                            parameters: ("SD_JWT_VC_example_in_OpenID4VCI".to_string()).into()
                        }),
                        scope: Some("SD_JWT_VC_example_in_OpenID4VCI".to_string()),
                        cryptographic_binding_methods_supported: vec!["jwk".to_string()],
                        credential_signing_alg_values_supported: vec!["ES256".to_string()],
                        proof_types_supported: vec![(
                            ProofType::Jwt,
                            KeyProofMetadata {
                                proof_signing_alg_values_supported: vec![Algorithm::ES256]
                            }
                        )]
                        .into_iter()
                        .collect(),
                        display: vec![serde_json::from_value(json!(        {
                          "name": "IdentityCredential",
                          "logo": {
                            "uri": "https://university.example.edu/public/logo.png",
                            "alt_text": "a square logo of a university"
                          },
                          "locale": "en-US",
                          "background_color": "#12107c",
                          "text_color": "#FFFFFF"
                        }))
                        .unwrap()],
                        claims: vec![
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "given_name".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![
                                    serde_json::from_value(json!({
                                        "name": "Given Name",
                                        "locale": "en-US"
                                    }))
                                    .unwrap(),
                                    serde_json::from_value(json!({
                                        "name": "Vorname",
                                        "locale": "de-DE"
                                    }))
                                    .unwrap()
                                ],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "family_name".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![
                                    serde_json::from_value(json!({
                                        "name": "Surname",
                                        "locale": "en-US"
                                    }))
                                    .unwrap(),
                                    serde_json::from_value(json!({
                                        "name": "Nachname",
                                        "locale": "de-DE"
                                    }))
                                    .unwrap()
                                ],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String("email".to_string())])
                                    .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "phone_number".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String("address".to_string())])
                                    .unwrap(),
                                mandatory: false,
                                display: vec![
                                    serde_json::from_value(json!({
                                        "name": "Place of residence",
                                        "locale": "en-US"
                                    }))
                                    .unwrap(),
                                    serde_json::from_value(json!({
                                        "name": "Wohnsitz",
                                        "locale": "de-DE"
                                    }))
                                    .unwrap()
                                ],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("locality".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("region".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("country".to_string())
                                ])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "birthdate".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "is_over_18".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "is_over_21".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                            ClaimDescription {
                                path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                    "is_over_65".to_string()
                                )])
                                .unwrap(),
                                mandatory: false,
                                display: vec![],
                            },
                        ]
                    }
                )]
                .into_iter()
                .collect()
            },
            from_str::<TestWrapper>(include_str!("../../tests/examples/credential_metadata_sd_jwt_vc.json")).unwrap()
        );
    }
}
