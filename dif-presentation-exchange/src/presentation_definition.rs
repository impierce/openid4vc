use crate::claims::{validate_claim_path, validate_claim_values, validate_claims, ClaimsContext};
use crate::meta::{validate_format, validate_meta, MetaContext};
use getset::Getters;
use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
use validator::{Validate, ValidationError, ValidationErrors};

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Getters, PartialEq, Clone, Serialize)]
pub struct PresentationDefinition {
    #[getset(get = "pub")]
    pub(crate) id: String,
    // All inputs listed in the `input_descriptors` array are required for submission, unless otherwise specified by a
    // Feature.
    #[getset(get = "pub")]
    pub(crate) input_descriptors: Vec<InputDescriptor>,
    pub(crate) name: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) format: Option<HashMap<ClaimFormatDesignation, ClaimFormatProperty>>,
}

/// As specified in https://identity.foundation/presentation-exchange/#input-descriptor-object.
/// All input descriptors MUST be satisfied, unless otherwise specified by a Feature.
#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Getters, PartialEq, Clone, Serialize)]
pub struct InputDescriptor {
    // Must not conflict with other input descriptors.
    #[getset(get = "pub")]
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) format: Option<HashMap<ClaimFormatDesignation, ClaimFormatProperty>>,
    #[getset(get = "pub")]
    pub(crate) constraints: Constraints,
    pub(crate) schema: Option<String>,
}

// Its value MUST be an array of one or more format-specific algorithmic identifier references
// TODO: fix this related to jwt_vc_json and jwt_vp_json: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-e.1
#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormatDesignation {
    Jwt,
    JwtVc,
    JwtVcJson,
    JwtVp,
    JwtVpJson,
    Ldp,
    LdpVc,
    LdpVp,
    AcVc,
    AcVp,
    MsoMdoc,
    #[serde(rename = "vc+sd-jwt")]
    VcSdJwt,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormatProperty {
    Alg(Vec<Algorithm>),
    ProofType(Vec<String>),
    #[serde(untagged)]
    SdJwt {
        #[serde(rename = "sd-jwt_alg_values", default, skip_serializing_if = "Vec::is_empty")]
        sd_jwt_alg_values: Vec<Algorithm>,
        #[serde(rename = "kb-jwt_alg_values", default, skip_serializing_if = "Vec::is_empty")]
        kb_jwt_alg_values: Vec<Algorithm>,
    },
}

#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Getters, Default, PartialEq, Clone, Serialize)]
pub struct Constraints {
    #[getset(get = "pub")]
    pub(crate) fields: Option<Vec<Field>>,
    // Omission of the `limit_disclosure` property indicates the Conforment Consumer MAY submit a response that contains
    // more than the data described in the `fields` array.
    #[getset(get = "pub")]
    pub(crate) limit_disclosure: Option<LimitDisclosure>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitDisclosure {
    Required,
    Preferred,
}

#[allow(dead_code)]
#[skip_serializing_none]
#[derive(Deserialize, Debug, Getters, Default, PartialEq, Clone, Serialize)]
pub struct Field {
    // The value of this property MUST be an array of ONE OR MORE JSONPath string expressions.
    // The ability to declare multiple expressions in this way allows the Verifier to account for format differences.
    #[getset(get = "pub")]
    pub(crate) path: Vec<String>,
    pub(crate) id: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) name: Option<String>,
    #[getset(get = "pub")]
    pub(crate) filter: Option<serde_json::Value>,
    // TODO: check default behaviour
    #[getset(get = "pub")]
    pub(crate) optional: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

#[derive(Debug, Serialize, Deserialize, Validate, PartialEq)]
pub struct CredentialQuery {
    #[validate(
        length(min = 1, message = "Credential ID must not be empty"),
        custom(function = "validate_credential_id")
    )]
    pub id: String,
    #[validate(custom(function = "validate_format"))]
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetaTypes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum MetaTypes {
    W3CFormatMeta { type_values: Vec<Vec<String>> },
    SdJwtMeta { vct_values: Vec<String> },
    MsoMdocMeta { doctype_value: String },
}

fn validate_credential_id(id: &str) -> Result<(), ValidationError> {
    if !id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ValidationError::new("credential_id_invalid_chars")
            .with_message("Credential id must contain only alphanumeric, underscore, or hyphen characters".into()));
    }
    Ok(())
}

impl CredentialQuery {
    pub fn validate_all(&self) -> Result<(), ValidationErrors> {
        self.validate()?;

        let meta_ctx = MetaContext { format: &self.format };

        if let Err(e) = validate_meta(&self.meta, &meta_ctx) {
            let mut errors = ValidationErrors::new();
            errors.add("meta", e);
            return Err(errors);
        }

        let claims_ctx = ClaimsContext {
            claim_sets: &self.claim_sets,
        };

        if let Err(e) = validate_claims(&self.claims, &claims_ctx) {
            let mut errors = ValidationErrors::new();
            errors.add("claims", e);
            return Err(errors);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct CredentialSetQuery {
    pub options: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustedAuthority {
    #[serde(rename = "type")]
    pub type_: String,
    pub values: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Validate)]
pub struct ClaimQuery {
    pub id: Option<String>,
    #[validate(custom(function = "validate_claim_path"))]
    pub path: Vec<ClaimPathElement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_claim_values"))]
    pub values: Option<Vec<ClaimValue>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ClaimPathElement {
    String(String),
    Integer(u64),
    Null,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;
    // OID4VP Credential Test Examples from
    // https://github.com/openid/OpenID4VP/tree/main/examples/query_lang
    #[test]
    fn test_oid4vp_example_simple_mdoc() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "my_credential".to_string(),
                    format: "mso_mdoc".to_string(),
                    multiple: None,
                    meta: Some(MetaTypes::MsoMdocMeta {
                        doctype_value: "org.iso.7367.1.mVRC".to_string()
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                    claims: vec![
                        ClaimQuery {
                            id: None,
                            path: vec![
                                ClaimPathElement::String("org.iso.7367.1".to_string()),
                                ClaimPathElement::String("vehicle_holder".to_string())
                            ],
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: vec![
                                ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                ClaimPathElement::String("first_name".to_string())
                            ],
                            values: None
                        }
                    ],
                    claim_sets: None
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!("../../oid4vp/tests/examples/query_lang/simple_mdoc.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_simple_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "my_credential".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(MetaTypes::SdJwtMeta {
                        vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                    claims: vec![
                        ClaimQuery {
                            id: None,
                            path: vec![ClaimPathElement::String("last_name".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: vec![ClaimPathElement::String("first_name".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: vec![
                                ClaimPathElement::String("address".to_string()),
                                ClaimPathElement::String("street_address".to_string())
                            ],
                            values: None
                        }
                    ],
                    claim_sets: None
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!("../../oid4vp/tests/examples/query_lang/simple.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_examples_value_matching_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "my_credential".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(MetaTypes::SdJwtMeta {
                        vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                    claims: vec![
                        ClaimQuery {
                            id: None,
                            path: vec![ClaimPathElement::String("last_name".to_string())],
                            values: Some(vec![ClaimValue::String("Doe".to_string())])
                        },
                        ClaimQuery {
                            id: None,
                            path: vec![ClaimPathElement::String("first_name".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: vec![
                                ClaimPathElement::String("address".to_string()),
                                ClaimPathElement::String("street_address".to_string())
                            ],
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: vec![ClaimPathElement::String("postal_code".to_string())],
                            values: Some(vec![
                                ClaimValue::String("90210".to_string()),
                                ClaimValue::String("90211".to_string())
                            ]),
                        },
                    ],
                    claim_sets: None
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!(
                "../../oid4vp/tests/examples/query_lang/value_matching_simple.json"
            ))
            .unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_claims_alternatives_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "pid".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    multiple: None,
                    meta: Some(MetaTypes::SdJwtMeta {
                        vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: None,
                    claims: vec![
                        ClaimQuery {
                            id: Some("a".to_string()),
                            path: vec![ClaimPathElement::String("last_name".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: Some("b".to_string()),
                            path: vec![ClaimPathElement::String("postal_code".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: Some("c".to_string()),
                            path: vec![ClaimPathElement::String("locality".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: Some("d".to_string()),
                            path: vec![ClaimPathElement::String("region".to_string())],
                            values: None
                        },
                        ClaimQuery {
                            id: Some("e".to_string()),
                            path: vec![ClaimPathElement::String("date_of_birth".to_string())],
                            values: None
                        },
                    ],
                    claim_sets: Some(vec![
                        vec!["a".to_string(), "c".to_string(), "d".to_string(), "e".to_string()],
                        vec!["a".to_string(), "b".to_string(), "e".to_string()]
                    ]),
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!(
                "../../oid4vp/tests/examples/query_lang/claims_alternatives.json"
            ))
            .unwrap()
        );
    }
    #[test]
    fn test_oid4vp_example_multi_credentials_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![
                    CredentialQuery {
                        id: "pid".to_string(),
                        format: "dc+sd-jwt".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("given_name".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("family_name".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "mdl".to_string(),
                        format: "mso_mdoc".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.7367.1.mVRC".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: vec![
                                    ClaimPathElement::String("org.iso.7367.1".to_string()),
                                    ClaimPathElement::String("vehicle_holder".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("first_name".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    }
                ],

                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!(
                "../../oid4vp/tests/examples/query_lang/multi_credentials.json"
            ))
            .unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_complex_mdoc() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![
                    CredentialQuery {
                        id: "mdl-id".to_string(),
                        format: "mso_mdoc".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.18013.5.1.mDL".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: Some("given_name".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: Some("family_name".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: Some("portrait".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("portrait".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "mdl-address".to_string(),
                        format: "mso_mdoc".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.18013.5.1.mDL".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: Some("resident_address".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_address".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: Some("resident_country".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_country".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "photo_card-id".to_string(),
                        format: "mso_mdoc".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.23220.photoid.1".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: Some("given_name".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: Some("family_name".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: Some("portrait".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("portrait".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "photo_card-address".to_string(),
                        format: "mso_mdoc".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.23220.photoid.1".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: Some("resident_address".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_address".to_string())
                                ],
                                values: None
                            },
                            ClaimQuery {
                                id: Some("resident_country".to_string()),
                                path: vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_country".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    }
                ],
                credential_sets: Some(vec![
                    CredentialSetQuery {
                        options: vec![vec!["mdl-id".to_string()], vec!["photo_card-id".to_string()]],
                        required: None
                    },
                    CredentialSetQuery {
                        options: vec![vec!["mdl-address".to_string()], vec!["photo_card-address".to_string()]],
                        required: Some(false),
                    }
                ])
            },
            from_str::<DcqlQuery>(include_str!("../../oid4vp/tests/examples/query_lang/complex_mdoc.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_credentials_alternatives_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![
                    CredentialQuery {
                        id: "pid".to_string(),
                        format: "dc+sd-jwt".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/identity_credential".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("given_name".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("family_name".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "other_pid".to_string(),
                        format: "dc+sd-jwt".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://othercredentials.example/pid".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("given_name".to_string()),],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("family_name".to_string()),],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "pid_reduced_cred_1".to_string(),
                        format: "dc+sd-jwt".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/reduced_identity_credential".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("family_name".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("given_name".to_string())],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "pid_reduced_cred_2".to_string(),
                        format: "dc+sd-jwt".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://cred.example/residence_credential".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("postal_code".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("locality".to_string())],
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: vec![ClaimPathElement::String("region".to_string()),],
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: "nice_to_have".to_string(),
                        format: "dc+sd-jwt".to_string(),
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://company.example/company_rewards".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: None,
                        claims: vec![ClaimQuery {
                            id: None,
                            path: vec![ClaimPathElement::String("rewards_number".to_string())],
                            values: None
                        }],
                        claim_sets: None
                    },
                ],

                credential_sets: Some(vec![
                    CredentialSetQuery {
                        options: vec![
                            vec!["pid".to_string()],
                            vec!["other_pid".to_string()],
                            vec!["pid_reduced_cred_1".to_string(), "pid_reduced_cred_2".to_string()]
                        ],
                        required: None
                    },
                    CredentialSetQuery {
                        options: vec![vec!["nice_to_have".to_string()]],
                        required: Some(false),
                    }
                ])
            },
            from_str::<DcqlQuery>(include_str!(
                "../../oid4vp/tests/examples/query_lang/credentials_alternatives.json"
            ))
            .unwrap()
        );
    }
    #[test]
    fn test_invalid_w3c_meta() {
        let invalid_json = r#"{
        "credentials": [
            {
                "id": "my_credential",
                "format": "ldp_vc",
                "meta": {
                    "wrong_values": [
                        ["https://example.com/credential"]
                    ]
                },
                claims: []
            }
        ]
 }"#;
        let result = from_str::<DcqlQuery>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_id() {
        // The ID field is empty
        let credential = CredentialQuery {
            id: "".to_string(),
            format: "ldp_vc".to_string(),
            multiple: None,
            meta: Some(MetaTypes::W3CFormatMeta {
                type_values: vec![vec!["https://example.com/credential".to_string()]],
            }),
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
            claims: vec![],
            claim_sets: None,
        };

        let result = credential.validate();
        assert!(result.is_err());

        if let Err(errors) = result {
            println!("Error: {:?}", errors);
        }
    }

    #[test]
    fn test_incorrect_id_format() {
        // The ID field contains invalid characters/formatting
        let credential = CredentialQuery {
            id: "abc!23*".to_string(),
            format: "ldp_vc".to_string(),
            multiple: None,
            meta: Some(MetaTypes::W3CFormatMeta {
                type_values: vec![vec!["https://example.com/credential".to_string()]],
            }),
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
            claims: vec![],
            claim_sets: None,
        };

        let result = credential.validate();
        assert!(result.is_err());

        if let Err(errors) = result {
            println!("Error: {:?}", errors);
        }
    }

    #[test]
    fn test_claim_without_id_when_claim_sets_present() {
        // A claim that has no ID, but claim_sets is present
        let invalid_json = r#"{
        "id": "credential_id",
        "format": "ldp_vc",
        "meta": {
            "type_values": [
                ["https://example.com/credential"]
            ]
        },
        "claims": [
            {
                "path": ["some_path"] 
                       }
        ],
        "claim_sets": [
            ["some_claim_id"]
        ]
    }"#;
        let result = serde_json::from_str::<CredentialQuery>(invalid_json);
        assert!(result.is_ok());

        // But validation should fail
        let credential_query = result.unwrap();
        let validation_result = credential_query.validate_all();
        assert!(validation_result.is_err());
    }

    #[test]
    fn test_claims_sets_references_unknown_id() {
        // A claim set that references an unknown claim ID
        let invalid_json = r#"
        {
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
                "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
                {
                    "id": "a",
                    "path": ["last_name"]
                },
                {
                "id": "b",
                    "path": ["postal_code"]
                },
                {
                    "id": "c",
                    "path": ["locality"]
                },
                {
                    "id": "d",
                    "path": ["region"]
                },
                {
                    "id": "e",
                    "path": ["date_of_birth"]
                }
            ],
            "claim_sets": [
                ["a", "c", "d", "e"],
                ["a", "b", "e", "unknown_id"]
            ]
        }
        "#;
        let result = serde_json::from_str::<CredentialQuery>(invalid_json);
        assert!(result.is_ok(), "Deserialization failed: {}", result.unwrap_err());

        let credential_query = result.unwrap();
        let validation_result = credential_query.validate_all();
        assert!(validation_result.is_err());

        let error_string = validation_result.unwrap_err().to_string();
        assert!(
            error_string.contains("Claim ID 'unknown_id' not found in claims at claim_set[1][3]"),
            "Unexpected error message: {}",
            error_string
        );
    }

    #[test]
    fn test_omitted_meta_is_ok() {
        let valid_json = r#"{
        "id": "my_credential",
        "format": "ldp_vc",
        "claims": []
    }"#;
        let result = from_str::<CredentialQuery>(valid_json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dcql_query() {
        let temporary = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "my_credential".to_string(),
                format: "mso_mdoc".to_string(),
                multiple: None,
                meta: Some(MetaTypes::SdJwtMeta {
                    vct_values: vec!["https://credentials.example.com/identity_credential".to_string()],
                }),
                trusted_authorities: None,
                require_cryptographic_holder_binding: None,
                claims: vec![],
                claim_sets: None,
            }],
            credential_sets: None,
        };
        temporary.validate().unwrap();
    }

    #[test]
    fn test_incorrect_metadata_format() {
        // The meta format does not correspond to the credential format
        let invalid_json = r#"{
            "id": "my_credential",
            "format": "dc+sd-jwt",
            "meta": {
                "type_values": [
                    ["https://example.com/credential"]
                ]
            },
            "claims": []
        }"#;

        let result = serde_json::from_str::<CredentialQuery>(invalid_json);
        assert!(result.is_ok());

        let credential = result.unwrap();
        let validation_result = credential.validate_all();
        assert!(validation_result.is_err());
    }

    #[test]
    fn test_invalid_meta_value() {
        // The credential format is correct, but the meta value format is not
        let invalid_json = r#"{
            "id": "my_credential",
            "format": "mso_mdoc",
            "meta": {
                "doctype_value": [
                    ["https://example.com/credential"]
                ]
            },
            "claims": []
        }"#;

        let result = serde_json::from_str::<CredentialQuery>(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_query_serialization_round_trip() {
        let original_credential = CredentialQuery {
            id: "basho".to_string(),
            format: "ldp_vc".to_string(),
            multiple: None,
            meta: Some(MetaTypes::W3CFormatMeta {
                type_values: vec![vec!["https://example.com/credential".to_string()]],
            }),
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
            claims: vec![ClaimQuery {
                id: None,
                path: vec![ClaimPathElement::String("line_number".to_string())],
                values: None,
            }],
            claim_sets: None,
        };
        let json = serde_json::to_string(&original_credential).expect("Failed to serialize");
        let deserialized: CredentialQuery = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(original_credential, deserialized);
    }

    #[test]
    fn test_credential_query_serialization() {
        let credential_query = CredentialQuery {
            id: "robbie".to_string(),
            format: "dc+sd-jwt".to_string(),
            multiple: None,
            meta: Some(MetaTypes::SdJwtMeta {
                vct_values: vec!["https://credentials.example.com/identity_credential".to_string()],
            }),
            trusted_authorities: None,
            require_cryptographic_holder_binding: None,
            claims: vec![
                ClaimQuery {
                    id: Some("basho".to_string()),
                    path: vec![ClaimPathElement::String("last_name".to_string())],
                    values: None,
                },
                ClaimQuery {
                    id: Some("casho".to_string()),
                    path: vec![ClaimPathElement::String("first_name".to_string())],
                    values: Some(vec![ClaimValue::String("Matsuo".to_string())]),
                },
            ],
            claim_sets: Some(vec![vec!["basho".to_string(), "casho".to_string()]]),
        };
        let json = serde_json::to_string_pretty(&credential_query).expect("Failed to serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Failed to parse serialized JSON");
        assert_eq!(parsed["id"], "robbie");
        assert_eq!(parsed["format"], "dc+sd-jwt");
        assert_eq!(
            parsed["meta"]["vct_values"][0],
            "https://credentials.example.com/identity_credential"
        );

        assert_eq!(parsed["claims"][0]["id"], "basho");
        assert_eq!(parsed["claims"][0]["path"][0], "last_name");
        assert_eq!(parsed["claims"][1]["id"], "casho");
        assert_eq!(parsed["claims"][1]["path"][0], "first_name");
        assert_eq!(parsed["claims"][1]["values"][0], "Matsuo");
        assert_eq!(parsed["claim_sets"][0][0], "basho");
        assert_eq!(parsed["claim_sets"][0][1], "casho");

        assert!(!parsed.as_object().unwrap().contains_key("multiple"));
        assert!(!parsed.as_object().unwrap().contains_key("trusted_authorities"));
        assert!(!parsed
            .as_object()
            .unwrap()
            .contains_key("require_cryptographic_holder_binding"));
    }

    #[test]
    fn test_skip_serializing_if_none() {}

    #[test]
    fn test_claim_format_property() {
        assert_eq!(
            ClaimFormatProperty::Alg(vec![Algorithm::EdDSA, Algorithm::ES256]),
            serde_json::from_str(r#"{"alg":["EdDSA","ES256"]}"#).unwrap()
        );

        assert_eq!(
            ClaimFormatProperty::ProofType(vec!["JsonWebSignature2020".to_string()]),
            serde_json::from_str(r#"{"proof_type":["JsonWebSignature2020"]}"#).unwrap()
        );

        assert_eq!(
            ClaimFormatProperty::SdJwt {
                sd_jwt_alg_values: vec![Algorithm::EdDSA],
                kb_jwt_alg_values: vec![Algorithm::ES256],
            },
            serde_json::from_str(r#"{"sd-jwt_alg_values":["EdDSA"],"kb-jwt_alg_values":["ES256"]}"#).unwrap()
        );
    }

    #[test]
    fn test_deserialize_presentation_definition() {
        assert_eq!(
            PresentationDefinition {
                id: "example_vc_ac_sd".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "id_credential".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::AcVc,
                        ClaimFormatProperty::ProofType(vec!["CLSignature2019".to_string()])
                    )])),
                    constraints: Constraints {
                        limit_disclosure: Some(LimitDisclosure::Required),
                        fields: Some(vec![
                            Field {
                                path: vec!["$.schema_id".to_string()],
                                filter: Some(serde_json::json!({
                                    "type": "string",
                                    "const": "did:indy:idu:test:3QowxFtwciWceMFr7WbwnM:2:BasicScheme:0\\.1"
                                })),
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.values.first_name".to_string()],
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.values.last_name".to_string()],
                                ..Default::default()
                            }
                        ]),
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!("../../oid4vp/tests/examples/request/pd_ac_vc_sd.json"))
                .unwrap()
        );

        assert_eq!(
            PresentationDefinition {
                id: "example_vc_ac".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "id_credential".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::AcVc,
                        ClaimFormatProperty::ProofType(vec!["CLSignature2019".to_string()])
                    )])),
                    constraints: Constraints {
                        fields: Some(vec![Field {
                            path: vec!["$.schema_id".to_string()],
                            filter: Some(serde_json::json!({
                                "type": "string",
                                "const": "did:indy:idu:test:3QowxFtwciWceMFr7WbwnM:2:BasicScheme:0\\.1"
                            })),
                            ..Default::default()
                        }]),
                        limit_disclosure: None,
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!("../../oid4vp/tests/examples/request/pd_ac_vc.json"))
                .unwrap()
        );

        assert_eq!(
            PresentationDefinition {
                id: "example_jwt_vc".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "id_credential".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::JwtVcJson,
                        ClaimFormatProperty::ProofType(vec!["JsonWebSignature2020".to_string()])
                    )])),
                    constraints: Constraints {
                        fields: Some(vec![Field {
                            path: vec!["$.vc.type".to_string()],
                            filter: Some(serde_json::json!({
                                "type": "array",
                                "contains": {
                                    "const": "IDCredential"
                                }
                            })),
                            ..Default::default()
                        }]),
                        limit_disclosure: None,
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!("../../oid4vp/tests/examples/request/pd_jwt_vc.json"))
                .unwrap()
        );

        assert_eq!(
            PresentationDefinition {
                id: "example_ldp_vc".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "id_credential".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::LdpVc,
                        ClaimFormatProperty::ProofType(vec!["Ed25519Signature2018".to_string()])
                    )])),
                    constraints: Constraints {
                        fields: Some(vec![Field {
                            path: vec!["$.type".to_string()],
                            filter: Some(serde_json::json!({
                                "type": "array",
                                "contains": {
                                    "const": "IDCredential"
                                }
                            })),
                            ..Default::default()
                        }]),
                        limit_disclosure: None,
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!("../../oid4vp/tests/examples/request/pd_ldp_vc.json"))
                .unwrap()
        );

        // TODO: report json file bug + add retention feature: https://identity.foundation/presentation-exchange/spec/v2.0.0/#retention-feature
        assert_eq!(
            PresentationDefinition {
                id: "mDL-sample-req".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "mDL".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::MsoMdoc,
                        ClaimFormatProperty::Alg(vec![Algorithm::EdDSA, Algorithm::ES256])
                    )])),
                    constraints: Constraints {
                        limit_disclosure: Some(LimitDisclosure::Required),
                        fields: Some(vec![
                            Field {
                                path: vec!["$.mdoc.doctype".to_string()],
                                filter: Some(serde_json::json!({
                                    "type": "string",
                                    "const": "org.iso.18013.5.1.mDL"
                                })),
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.mdoc.namespace".to_string()],
                                filter: Some(serde_json::json!({
                                    "type": "string",
                                    "const": "org.iso.18013.5.1"
                                })),
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.mdoc.family_name".to_string()],
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.mdoc.portrait".to_string()],
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.mdoc.driving_privileges".to_string()],
                                ..Default::default()
                            },
                        ]),
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!(
                "../../oid4vp/tests/examples/request/pd_mdl_iso_cbor.json"
            ))
            .unwrap()
        );

        assert_eq!(
            PresentationDefinition {
                id: "example with selective disclosure".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "ID card with constraints".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::LdpVc,
                        ClaimFormatProperty::ProofType(vec!["Ed25519Signature2018".to_string()])
                    )])),
                    constraints: Constraints {
                        fields: Some(vec![
                            Field {
                                path: vec!["$.type".to_string()],
                                filter: Some(serde_json::json!({
                                    "type": "string",
                                    "pattern": "IDCardCredential"
                                })),
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.credentialSubject.given_name".to_string()],
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.credentialSubject.family_name".to_string()],
                                ..Default::default()
                            },
                            Field {
                                path: vec!["$.credentialSubject.birthdate".to_string()],
                                ..Default::default()
                            }
                        ]),
                        limit_disclosure: Some(LimitDisclosure::Required),
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!(
                "../../oid4vp/tests/examples/request/vp_token_type_and_claims.json"
            ))
            .unwrap()
        );

        assert_eq!(
            PresentationDefinition {
                id: "vp token example".to_string(),
                name: None,
                format: None,
                input_descriptors: vec![InputDescriptor {
                    id: "id card credential".to_string(),
                    name: None,
                    purpose: None,
                    format: Some(HashMap::from_iter(vec![(
                        ClaimFormatDesignation::LdpVc,
                        ClaimFormatProperty::ProofType(vec!["Ed25519Signature2018".to_string()])
                    )])),
                    constraints: Constraints {
                        fields: Some(vec![Field {
                            path: vec!["$.type".to_string()],
                            filter: Some(serde_json::json!({
                                "type": "string",
                                "pattern": "IDCardCredential"
                            })),
                            ..Default::default()
                        }]),
                        limit_disclosure: None,
                    },
                    schema: None,
                }],
                purpose: None,
            },
            from_str::<PresentationDefinition>(include_str!(
                "../../oid4vp/tests/examples/request/vp_token_type_only.json"
            ))
            .unwrap()
        );
    }
}
