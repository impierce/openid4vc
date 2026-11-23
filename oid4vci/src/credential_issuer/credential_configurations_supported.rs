use std::collections::HashMap;

use crate::{
    credential_format_profiles::{CredentialFormats, WithParameters},
    proof::{KeyProofMetadata, ProofType},
};
use oid4vc_core::claim_path_pointer::{
    ClaimPathPointer, ClaimPathSemantics, ClaimsDescriptionError, check_claims_description_paths,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// Credentials Supported object as described here: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.11.1>
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialConfigurationsSupportedObject {
    /// This field is flattened into a `format` field and optionally extra format-specific fields.
    #[serde(flatten)]
    #[cfg_attr(
        feature = "utoipa",
        schema(value_type = crate::credential_format_profiles::CredentialFormatsWithParametersSchema)
    )]
    pub credential_format: CredentialFormats<WithParameters>,
    // Use `Scope` from oid4vc-core/src/scope.rs.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptographic_binding_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_signing_alg_values_supported: Vec<AlgIdentifier>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub proof_types_supported: HashMap<ProofType, KeyProofMetadata>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub credential_metadata: Option<CredentialMetadata>,
}

/// Claims and display information associated with a supported Credential Configuration.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CredentialMetadata {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub claims: Option<Vec<ClaimDescription>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display: Option<Vec<CredentialConfigurationsSupportedDisplay>>,
}

/// A JSON Web Algorithm identifier represented by either its string or integer form.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum AlgIdentifier {
    String(String),
    Integer(i32),
}

impl CredentialConfigurationsSupportedObject {
    /// Checks the claims descriptions in `credential_metadata` against OpenID4VCI 1.0, Appendix B.3: no claim is
    /// described twice, and no two descriptions contradict each other. Each path must also be able to address a
    /// claim in a credential of the format (Appendix C). See [`check_claims_description_paths`] for the rules.
    ///
    /// - `mso_mdoc` (Appendix C.2): a path starts with the namespace and the data element identifier, and a
    ///   non-negative integer can be a map key.
    /// - `jwt_vc_json`, `jwt_vc_json-ld`, `ldp_vc`, `dc+sd-jwt` and `vc+sd-jwt` (Appendix C.1): a path starts with
    ///   a key of the top-level object, and a non-negative integer is an array index.
    /// - A format this crate does not know: a non-negative integer implies an array, as Appendix B.3 reads, and
    ///   nothing is assumed about where a path starts.
    ///
    /// Nothing in this crate calls it: an issuer can run it before publishing its metadata, and a Wallet before it
    /// uses `claims`.
    pub fn check_claims_descriptions(&self) -> Result<(), ClaimsDescriptionError> {
        let Some(claims) = self
            .credential_metadata
            .as_ref()
            .and_then(|credential_metadata| credential_metadata.claims.as_ref())
        else {
            return Ok(());
        };
        let semantics = match self.credential_format {
            CredentialFormats::MsoMdoc(_) => ClaimPathSemantics::Mdoc,
            CredentialFormats::JwtVcJson(_)
            | CredentialFormats::JwtVcJsonLd(_)
            | CredentialFormats::LdpVc(_)
            | CredentialFormats::DcSdJwt(_)
            | CredentialFormats::VcSdJwt(_) => ClaimPathSemantics::Json,
            CredentialFormats::Unknown => ClaimPathSemantics::Unknown,
        };
        check_claims_description_paths(claims.iter().map(|claim| &claim.path), semantics)
    }
}

/// Metadata describing a claim addressable through a Claim Path Pointer.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClaimDescription {
    pub path: ClaimPathPointer,
    #[serde(default)]
    pub mandatory: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub display: Vec<ClaimDescriptionDisplay>,
}

/// Display properties of a claim for one language, as OpenID4VCI 1.0, Appendix B.2 defines them in `display`.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ClaimDescriptionDisplay {
    /// The display name of the claim.
    pub name: Option<String>,
    /// The language of this object, a BCP47 language tag.
    pub locale: Option<String>,
    /// The other parameters of the object: Appendix B.2 lists `name` and `locale` as "a non-exhaustive list of valid
    /// parameters". They are kept as received and serialized next to `name` and `locale`; this crate does not
    /// interpret them. Do not put `name` or `locale` here: they have their own fields.
    #[serde(flatten)]
    #[cfg_attr(feature = "utoipa", schema(additional_properties))]
    pub additional_parameters: serde_json::Map<String, serde_json::Value>,
}

/// Logo metadata associated with a supported Credential Configuration.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Logo {
    pub uri: Url,
    pub alt_text: Option<String>,
}

/// Background image metadata associated with a supported Credential Configuration.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Image {
    pub uri: Url,
}

// TODO: implement builder pattern for this struct.
/// Localized display metadata for a supported Credential Configuration.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
        CredentialFormats, Parameters,
        w3c_verifiable_credentials::{jwt_vc_json, ldp_vc},
    };
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathError};
    use serde_json::{from_str, json};
    use std::collections::HashMap;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestWrapper {
        credential_configurations_supported: HashMap<String, CredentialConfigurationsSupportedObject>,
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/main/1.0/examples

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
                                ]
                            })
                            .into()
                        }),
                        scope: Some("UniversityDegree".to_string()),
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec![AlgIdentifier::String("ES256".to_string())],
                        proof_types_supported: vec![(
                            ProofType::Jwt,
                            KeyProofMetadata {
                                proof_signing_alg_values_supported: vec![AlgIdentifier::String("ES256".to_string())]
                            }
                        )]
                        .into_iter()
                        .collect(),
                        credential_metadata: Some(CredentialMetadata {
                            claims: Some(vec![
                                ClaimDescription {
                                    path: ClaimPathPointer::try_new(vec![
                                        ClaimPathElement::String("credentialSubject".to_string()),
                                        ClaimPathElement::String("given_name".to_string())
                                    ])
                                    .unwrap(),
                                    mandatory: false,
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "Given Name",
                                            "locale": "en-US"
                                        }))
                                        .unwrap()
                                    ],
                                },
                                ClaimDescription {
                                    path: ClaimPathPointer::try_new(vec![
                                        ClaimPathElement::String("credentialSubject".to_string()),
                                        ClaimPathElement::String("family_name".to_string())
                                    ])
                                    .unwrap(),
                                    mandatory: false,
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "Surname",
                                            "locale": "en-US"
                                        }))
                                        .unwrap()
                                    ],
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
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "GPA",
                                        }))
                                        .unwrap()
                                    ],
                                }
                            ]),
                            display: Some(vec![CredentialConfigurationsSupportedDisplay {
                                name: "University Credential".to_string(),
                                locale: Some("en-US".to_string()),
                                logo: Some(Logo {
                                    uri: Url::parse("https://university.example.edu/public/logo.png",).unwrap(),
                                    alt_text: Some("a square logo of a university".to_string()),
                                }),
                                description: None,
                                background_image: None,
                                background_color: Some("#12107c".to_string()),
                                text_color: Some("#FFFFFF".to_string()),
                            }]),
                        })
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
                                ]
                            })
                            .into()
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec![AlgIdentifier::String(
                            "Ed25519Signature2018".to_string()
                        )],
                        proof_types_supported: HashMap::new(),
                        credential_metadata: Some(CredentialMetadata {
                            display: Some(vec![
                                serde_json::from_value(json!({
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
                                .unwrap()
                            ]),
                            claims: Some(vec![
                                ClaimDescription {
                                    path: ClaimPathPointer::try_new(vec![
                                        ClaimPathElement::String("credentialSubject".to_string()),
                                        ClaimPathElement::String("given_name".to_string())
                                    ])
                                    .unwrap(),
                                    mandatory: false,
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "Given Name",
                                            "locale": "en-US"
                                        }))
                                        .unwrap()
                                    ],
                                },
                                ClaimDescription {
                                    path: ClaimPathPointer::try_new(vec![
                                        ClaimPathElement::String("credentialSubject".to_string()),
                                        ClaimPathElement::String("family_name".to_string())
                                    ])
                                    .unwrap(),
                                    mandatory: false,
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "Surname",
                                            "locale": "en-US"
                                        }))
                                        .unwrap()
                                    ],
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
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "GPA",
                                        }))
                                        .unwrap()
                                    ],
                                }
                            ])
                        },)
                    }
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
                            AlgIdentifier::Integer(-7),
                            AlgIdentifier::Integer(-9)
                        ],
                        proof_types_supported: HashMap::new(),
                        credential_metadata: Some(CredentialMetadata {
                            display: Some(vec![
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
                            ]),
                            claims: Some(vec![
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
                                    display: vec![
                                        serde_json::from_value(json!({
                                            "name": "Surname",
                                            "locale": "en-US"
                                        }))
                                        .unwrap()
                                    ],
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
                            ])
                        })
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
                        credential_signing_alg_values_supported: vec![AlgIdentifier::String("ES256".to_string())],
                        proof_types_supported: vec![(
                            ProofType::Jwt,
                            KeyProofMetadata {
                                proof_signing_alg_values_supported: vec![AlgIdentifier::String("ES256".to_string())]
                            }
                        )]
                        .into_iter()
                        .collect(),
                        credential_metadata: Some(CredentialMetadata {
                            display: Some(vec![
                                serde_json::from_value(json!(        {
                                  "name": "IdentityCredential",
                                  "logo": {
                                    "uri": "https://university.example.edu/public/logo.png",
                                    "alt_text": "a square logo of a university"
                                  },
                                  "locale": "en-US",
                                  "background_color": "#12107c",
                                  "text_color": "#FFFFFF"
                                }))
                                .unwrap()
                            ]),
                            claims: Some(vec![
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
                                    path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                        "email".to_string()
                                    )])
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
                                    path: ClaimPathPointer::try_new(vec![ClaimPathElement::String(
                                        "address".to_string()
                                    )])
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
                            ])
                        })
                    }
                )]
                .into_iter()
                .collect()
            },
            from_str::<TestWrapper>(include_str!("../../tests/examples/credential_metadata_sd_jwt_vc.json")).unwrap()
        );
    }

    #[test]
    fn a_claim_display_object_keeps_its_additional_parameters() {
        let json = json!({ "name": "Nationality", "locale": "en", "format": "country", "x-order": 3 });
        let display: ClaimDescriptionDisplay = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(display.name.as_deref(), Some("Nationality"));
        assert_eq!(display.locale.as_deref(), Some("en"));
        // `name` and `locale` are in their own fields, not in the map.
        assert_eq!(
            display.additional_parameters,
            json!({ "format": "country", "x-order": 3 })
                .as_object()
                .unwrap()
                .clone()
        );
        assert_eq!(serde_json::to_value(&display).unwrap(), json);
    }

    /// Appendix B.2: `name` is OPTIONAL.
    #[test]
    fn a_claim_display_object_without_name_parses() {
        for json in [json!({ "locale": "en" }), json!({ "format": "uri" }), json!({})] {
            let display: ClaimDescriptionDisplay = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(display.name, None);
            assert_eq!(serde_json::to_value(&display).unwrap(), json);
        }
    }

    /// The display objects of the claims in the specification examples have no additional parameters, and serialize
    /// to exactly the JSON they were read from.
    #[test]
    fn claim_display_objects_without_additional_parameters_serialize_as_before() {
        for example in [
            include_str!("../../tests/examples/credential_metadata_jwt_vc_json.json"),
            include_str!("../../tests/examples/credential_metadata_ldp_vc.json"),
            include_str!("../../tests/examples/credential_metadata_mso_mdoc.json"),
            include_str!("../../tests/examples/credential_metadata_sd_jwt_vc.json"),
        ] {
            let json: serde_json::Value = from_str(example).unwrap();
            let parsed: TestWrapper = from_str(example).unwrap();
            for (id, configuration) in &parsed.credential_configurations_supported {
                let claims = configuration
                    .credential_metadata
                    .as_ref()
                    .and_then(|credential_metadata| credential_metadata.claims.as_ref())
                    .unwrap();
                let claims_json = json["credential_configurations_supported"][id]["credential_metadata"]["claims"]
                    .as_array()
                    .unwrap();
                assert_eq!(claims.len(), claims_json.len());
                for (claim, claim_json) in claims.iter().zip(claims_json) {
                    let display_json = claim_json.get("display").cloned().unwrap_or(json!([]));
                    for display in &claim.display {
                        assert!(display.additional_parameters.is_empty(), "{id}: {display:?}");
                    }
                    assert_eq!(serde_json::to_value(&claim.display).unwrap(), display_json, "{id}");
                }
                assert_eq!(configuration.check_claims_descriptions(), Ok(()), "{id}");
            }
        }
    }

    /// The training record example of impierce/openid4vc#235, verbatim.
    #[test]
    fn the_training_record_of_the_issue_keeps_its_display_objects_and_passes_appendix_b3() {
        let json = json!({
            "format": "vc+sd-jwt",
            "credential_definition": { "type": ["VerifiableCredential", "TrainingRecord"] },
            "credential_metadata": {
                "display": [{ "name": "Training Record" }],
                "claims": [
                    { "path": ["credentialSubject", "Trainee"], "mandatory": true, "display": [{ "name": "Trainee" }] },
                    { "path": ["credentialSubject", "Trainee", "Full name"], "mandatory": true, "display": [{ "name": "Full name" }] },
                    { "path": ["credentialSubject", "Trainee", "Nationality"], "display": [{ "name": "Nationality", "format": "country" }] },
                    { "path": ["credentialSubject", "Skills"], "display": [{ "name": "Skills" }] },
                    { "path": ["credentialSubject", "Websites"], "display": [{ "name": "Websites" }] },
                    { "path": ["credentialSubject", "Websites", null], "display": [{ "format": "uri" }] },
                    { "path": ["credentialSubject", "Courses"], "mandatory": true, "display": [{ "name": "Courses", "format": "table" }] },
                    { "path": ["credentialSubject", "Courses", null, "Code"], "mandatory": true, "display": [{ "name": "Code" }] },
                    { "path": ["credentialSubject", "Courses", null, "Country"], "display": [{ "name": "Country", "format": "country" }] }
                ]
            }
        });
        let configuration: CredentialConfigurationsSupportedObject = serde_json::from_value(json.clone()).unwrap();
        let claims = configuration
            .credential_metadata
            .as_ref()
            .unwrap()
            .claims
            .as_ref()
            .unwrap();

        let websites_items = &claims[5].display[0];
        assert_eq!(websites_items.name, None);
        assert_eq!(websites_items.additional_parameters["format"], json!("uri"));
        assert_eq!(claims[6].display[0].additional_parameters["format"], json!("table"));
        assert_eq!(configuration.check_claims_descriptions(), Ok(()));

        // An issuer serializes the same display objects.
        let claims_json = json["credential_metadata"]["claims"].as_array().unwrap();
        for (claim, claim_json) in claims.iter().zip(claims_json) {
            assert_eq!(serde_json::to_value(&claim.display).unwrap(), claim_json["display"]);
        }
        // The rest of the metadata is the same too, except that `mandatory` is always written: the five claims
        // that leave it out get its default, `false`.
        let mut expected = json.clone();
        for claim in expected["credential_metadata"]["claims"].as_array_mut().unwrap() {
            claim
                .as_object_mut()
                .unwrap()
                .entry("mandatory")
                .or_insert(json!(false));
        }
        assert_eq!(serde_json::to_value(&configuration).unwrap(), expected);
    }

    fn configuration_with_claims(
        format: serde_json::Value,
        paths: serde_json::Value,
    ) -> CredentialConfigurationsSupportedObject {
        let mut json = format;
        json["credential_metadata"] = json!({
            "claims": paths.as_array().unwrap().iter().map(|path| json!({ "path": path })).collect::<Vec<_>>()
        });
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn check_claims_descriptions_applies_appendix_b3_with_the_semantics_of_the_format() {
        let paths = json!([
            ["org.iso.18013.5.1", "driving_privileges", 1],
            ["org.iso.18013.5.1", "driving_privileges", "codes"]
        ]);

        // For mso_mdoc, an integer can be a map key (Appendix C.2).
        let mdoc = configuration_with_claims(
            json!({ "format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL" }),
            paths.clone(),
        );
        assert_eq!(mdoc.check_claims_descriptions(), Ok(()));

        // For every other format it is an array index (Appendix C.1).
        let sd_jwt = configuration_with_claims(
            json!({ "format": "dc+sd-jwt", "vct": "https://example.org/mDL" }),
            paths,
        );
        assert!(matches!(
            sd_jwt.check_claims_descriptions(),
            Err(ClaimsDescriptionError::ArrayAndObject { .. })
        ));

        let repeated = configuration_with_claims(
            json!({ "format": "dc+sd-jwt", "vct": "https://example.org/mDL" }),
            json!([["given_name"], ["given_name"]]),
        );
        assert!(matches!(
            repeated.check_claims_descriptions(),
            Err(ClaimsDescriptionError::RepeatedClaim { .. })
        ));

        // Without claims there is nothing to check.
        let without_claims: CredentialConfigurationsSupportedObject =
            serde_json::from_value(json!({ "format": "dc+sd-jwt", "vct": "https://example.org/mDL" })).unwrap();
        assert_eq!(without_claims.check_claims_descriptions(), Ok(()));
    }

    #[test]
    fn check_claims_descriptions_refuses_paths_that_cannot_address_a_claim_of_the_format() {
        // An ISO mdoc path starts with the namespace and the data element identifier (Appendix C.2).
        let mdoc = configuration_with_claims(
            json!({ "format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL" }),
            json!([["org.iso.18013.5.1", "given_name"], ["org.iso.18013.5.1"]]),
        );
        assert_eq!(
            mdoc.check_claims_descriptions(),
            Err(ClaimsDescriptionError::InvalidPath(
                ClaimPathError::NoMdocNamespaceAndDataElement {
                    path: serde_json::from_value(json!(["org.iso.18013.5.1"])).unwrap()
                }
            ))
        );

        // A path into a JSON-based credential starts with a key of the top-level object (Appendix C.1.1).
        for format in [
            json!({ "format": "dc+sd-jwt", "vct": "https://example.org/mDL" }),
            json!({ "format": "jwt_vc_json", "credential_definition": { "type": ["VerifiableCredential"] } }),
        ] {
            let json_based = configuration_with_claims(format, json!([["given_name"], [null, "given_name"]]));
            assert_eq!(
                json_based.check_claims_descriptions(),
                Err(ClaimsDescriptionError::InvalidPath(ClaimPathError::JsonRootAsArray {
                    path: serde_json::from_value(json!([null, "given_name"])).unwrap()
                }))
            );
        }

        // For a format this crate does not know, nothing is assumed about where a path starts, and Appendix B.3 is
        // applied as it reads.
        let unknown =
            configuration_with_claims(json!({ "format": "example_format" }), json!([[0, "type"], [0, "name"]]));
        assert_eq!(unknown.credential_format, CredentialFormats::Unknown);
        assert_eq!(unknown.check_claims_descriptions(), Ok(()));
        let unknown = configuration_with_claims(
            json!({ "format": "example_format" }),
            json!([["degrees", 0], ["degrees", "type"]]),
        );
        assert!(matches!(
            unknown.check_claims_descriptions(),
            Err(ClaimsDescriptionError::ArrayAndObject { .. })
        ));
    }
}
