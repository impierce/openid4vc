use std::collections::HashMap;

use crate::{
    credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters},
    proof::{KeyProofMetadata, ProofType},
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credentials Supported object as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-13.html#section-11.2.3-2.11.1
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
    pub display: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub claims: Vec<IssuerMetadataClaim>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct IssuerMetadataClaim {
    // TODO: This should be a `ClaimPathPointer`
    pub path: Vec<String>,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub display: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{jwt_vc_json, ldp_vc, CredentialSubject},
        CredentialFormats, Parameters,
    };
    use jsonwebtoken::Algorithm;
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
                        display: vec![json!({
                            "name": "University Credential",
                            "locale": "en-US",
                            "logo": {
                                "uri": "https://university.example.edu/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        })],
                        claims: vec![
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "given_name".to_string()],
                                mandatory: false,
                                display: vec![json!({
                                    "name": "Given Name",
                                    "locale": "en-US"
                                })],
                            },
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "family_name".to_string()],
                                mandatory: false,
                                display: vec![json!({
                                    "name": "Surname",
                                    "locale": "en-US"
                                })],
                            },
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "degree".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "gpa".to_string()],
                                mandatory: true,
                                display: vec![json!({
                                    "name": "GPA",
                                })],
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
                        display: vec![json!({
                                "name": "University Credential",
                                "locale": "en-US",
                                "logo": {
                                    "uri": "https://university.example.edu/public/logo.png",
                                    "alt_text": "a square logo of a university"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }
                        )],
                        claims: vec![
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "given_name".to_string()],
                                mandatory: false,
                                display: vec![json!({
                                    "name": "Given Name",
                                    "locale": "en-US"
                                })],
                            },
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "family_name".to_string()],
                                mandatory: false,
                                display: vec![json!({
                                    "name": "Surname",
                                    "locale": "en-US"
                                })],
                            },
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "degree".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["credentialSubject".to_string(), "gpa".to_string()],
                                mandatory: true,
                                display: vec![json!({
                                    "name": "GPA",
                                })],
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
                            json!({
                                "name": "Mobile Driving License",
                                "locale": "en-US",
                                "logo": {
                                    "uri": "https://state.example.org/public/mdl.png",
                                    "alt_text": "state mobile driving license"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }),
                            json!({
                                "name": "モバイル運転免許証",
                                "locale": "ja-JP",
                                "logo": {
                                    "uri": "https://state.example.org/public/mdl.png",
                                    "alt_text": "米国州発行のモバイル運転免許証"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            })
                        ],
                        claims: vec![
                            IssuerMetadataClaim {
                                path: vec!["org.iso.18013.5.1".to_string(), "given_name".to_string()],
                                mandatory: false,
                                display: vec![
                                    json!({
                                        "name": "Given Name",
                                        "locale": "en-US"
                                    }),
                                    json!({
                                        "name": "名前",
                                        "locale": "ja-JP"
                                    })
                                ],
                            },
                            IssuerMetadataClaim {
                                path: vec!["org.iso.18013.5.1".to_string(), "family_name".to_string()],
                                mandatory: false,
                                display: vec![json!({
                                    "name": "Surname",
                                    "locale": "en-US"
                                })],
                            },
                            IssuerMetadataClaim {
                                path: vec!["org.iso.18013.5.1".to_string(), "birth_date".to_string()],
                                mandatory: true,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["org.iso.18013.5.1.aamva".to_string(), "organ_donor".to_string()],
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
                        display: vec![json!(        {
                          "name": "IdentityCredential",
                          "logo": {
                            "uri": "https://university.example.edu/public/logo.png",
                            "alt_text": "a square logo of a university"
                          },
                          "locale": "en-US",
                          "background_color": "#12107c",
                          "text_color": "#FFFFFF"
                        })],
                        claims: vec![
                            IssuerMetadataClaim {
                                path: vec!["given_name".to_string()],
                                mandatory: false,
                                display: vec![
                                    json!({
                                        "name": "Given Name",
                                        "locale": "en-US"
                                    }),
                                    json!({
                                        "name": "Vorname",
                                        "locale": "de-DE"
                                    })
                                ],
                            },
                            IssuerMetadataClaim {
                                path: vec!["family_name".to_string()],
                                mandatory: false,
                                display: vec![
                                    json!({
                                        "name": "Surname",
                                        "locale": "en-US"
                                    }),
                                    json!({
                                        "name": "Nachname",
                                        "locale": "de-DE"
                                    })
                                ],
                            },
                            IssuerMetadataClaim {
                                path: vec!["email".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["phone_number".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["address".to_string()],
                                mandatory: false,
                                display: vec![
                                    json!({
                                        "name": "Place of residence",
                                        "locale": "en-US"
                                    }),
                                    json!({
                                        "name": "Wohnsitz",
                                        "locale": "de-DE"
                                    })
                                ],
                            },
                            IssuerMetadataClaim {
                                path: vec!["address".to_string(), "street_address".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["address".to_string(), "locality".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["address".to_string(), "region".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["address".to_string(), "country".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["birthdate".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["is_over_18".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["is_over_21".to_string()],
                                mandatory: false,
                                display: vec![],
                            },
                            IssuerMetadataClaim {
                                path: vec!["is_over_65".to_string()],
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
