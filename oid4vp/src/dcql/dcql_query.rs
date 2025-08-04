use super::claims::{validate_claims, ClaimsContext};
use super::meta::{validate_meta, MetaContext};
use nutype::nutype;
use oid4vc_core::claim_path_pointer::{ClaimPathPointer, ClaimValues};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashSet;
use validator::{Validate, ValidationError, ValidationErrors};

#[nutype(
    validate(not_empty, predicate = valid_credential_query_id),
    derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq, Display, AsRef)
)]
pub struct CredentialQueryId(String);
fn valid_credential_query_id(s: &str) -> bool {
    s.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Validate)]
pub struct DcqlQuery {
    pub credentials: Vec<CredentialQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Validate)]
pub struct CredentialQuery {
    pub id: CredentialQueryId,
    pub format: Format,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiple: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetaTypes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    #[serde(default = "default_as_true", skip_serializing_if = "Option::is_none")]
    pub require_cryptographic_holder_binding: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimQuery>,
    //TODO Create nutype to create a new type with non-empty predicate. As ref see CredentialQueryId above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

fn default_as_true() -> Option<bool> {
    Some(true)
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum MetaTypes {
    W3CFormatMeta { type_values: Vec<Vec<String>> },
    SdJwtMeta { vct_values: Vec<String> },
    MsoMdocMeta { doctype_value: String },
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub enum Format {
    #[serde(rename = "ldp_vc")]
    LdpVc,
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
}
impl DcqlQuery {
    pub fn validate_all(&self) -> Result<(), ValidationErrors> {
        self.validate()?;

        // Check for duplicate credential IDs as the same id must not be present in the Authorization Request more than once.
        let mut seen_ids = HashSet::new();
        for (index, credential) in self.credentials.iter().enumerate() {
            if !seen_ids.insert(&credential.id) {
                let mut errors = ValidationErrors::new();
                let validation_error = ValidationError::new("duplicate_credential_id")
                    .with_message(format!("Duplicate credential ID '{}' at index {}", credential.id, index).into());
                errors.add("credentials", validation_error);
                return Err(errors);
            }
        }
        for credential in &self.credentials {
            credential.validate_all()?;
        }

        Ok(())
    }
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct CredentialSetQuery {
    //TODO: Create nutype  with non-empty predicate (see CredentialQueryId)
    pub options: Vec<Vec<String>>,
    #[serde(default = "default_as_true", skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct TrustedAuthority {
    #[serde(rename = "type")]
    //TODO: type_ should have stronger typing, see types defined by the spec:
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#name-authority-key-identifier
    pub type_: String,
    pub values: Vec<String>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Validate, Clone)]
pub struct ClaimQuery {
    //TODO: Use nutype for id, see CredentialQueryId as reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub path: ClaimPathPointer,
    pub values: Option<ClaimValues>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer, ClaimValue, ClaimValues};
    use serde_json::from_str;
    // OID4VP Credential Test Examples from
    // https://github.com/openid/OpenID4VP/tree/main/examples/query_lang

    fn test_credential_query_id(id: &str) -> CredentialQueryId {
        CredentialQueryId::try_new(id.to_string()).unwrap()
    }

    fn test_claim_path(elements: Vec<ClaimPathElement>) -> ClaimPathPointer {
        ClaimPathPointer::try_new(elements).unwrap()
    }

    fn test_claim_values(values: Vec<ClaimValue>) -> ClaimValues {
        ClaimValues::try_new(values).unwrap()
    }
    #[test]
    fn test_oid4vp_example_simple_mdoc() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: test_credential_query_id("my_credential"),
                    format: Format::MsoMdoc,
                    multiple: None,
                    meta: Some(MetaTypes::MsoMdocMeta {
                        doctype_value: "org.iso.7367.1.mVRC".to_string()
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                    claims: vec![
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![
                                ClaimPathElement::String("org.iso.7367.1".to_string()),
                                ClaimPathElement::String("vehicle_holder".to_string())
                            ]),
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![
                                ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                ClaimPathElement::String("first_name".to_string())
                            ]),
                            values: None
                        }
                    ],
                    claim_sets: None
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!("../../tests/examples/query_lang/simple_mdoc.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_simple_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: test_credential_query_id("my_credential"),
                    format: Format::DcSdJwt,
                    multiple: None,
                    meta: Some(MetaTypes::SdJwtMeta {
                        vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                    claims: vec![
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![ClaimPathElement::String("last_name".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![ClaimPathElement::String("first_name".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![
                                ClaimPathElement::String("address".to_string()),
                                ClaimPathElement::String("street_address".to_string())
                            ]),
                            values: None
                        }
                    ],
                    claim_sets: None
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!("../../tests/examples/query_lang/simple.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_examples_value_matching_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: test_credential_query_id("my_credential"),
                    format: Format::DcSdJwt,
                    multiple: None,
                    meta: Some(MetaTypes::SdJwtMeta {
                        vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                    claims: vec![
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![ClaimPathElement::String("last_name".to_string())]),
                            values: Some(test_claim_values(vec![ClaimValue::String("Doe".to_string())]))
                        },
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![ClaimPathElement::String("first_name".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![
                                ClaimPathElement::String("address".to_string()),
                                ClaimPathElement::String("street_address".to_string())
                            ]),
                            values: None
                        },
                        ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![ClaimPathElement::String("postal_code".to_string())]),
                            values: Some(test_claim_values(vec![
                                ClaimValue::String("90210".to_string()),
                                ClaimValue::String("90211".to_string())
                            ])),
                        },
                    ],
                    claim_sets: None
                }],
                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!(
                "../../tests/examples/query_lang/value_matching_simple.json"
            ))
            .unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_claims_alternatives_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: test_credential_query_id("pid"),
                    format: Format::DcSdJwt,
                    multiple: None,
                    meta: Some(MetaTypes::SdJwtMeta {
                        vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                    }),
                    trusted_authorities: None,
                    require_cryptographic_holder_binding: Some(true),
                    claims: vec![
                        ClaimQuery {
                            id: Some("a".to_string()),
                            path: test_claim_path(vec![ClaimPathElement::String("last_name".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: Some("b".to_string()),
                            path: test_claim_path(vec![ClaimPathElement::String("postal_code".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: Some("c".to_string()),
                            path: test_claim_path(vec![ClaimPathElement::String("locality".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: Some("d".to_string()),
                            path: test_claim_path(vec![ClaimPathElement::String("region".to_string())]),
                            values: None
                        },
                        ClaimQuery {
                            id: Some("e".to_string()),
                            path: test_claim_path(vec![ClaimPathElement::String("date_of_birth".to_string())]),
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
            from_str::<DcqlQuery>(include_str!("../../tests/examples/query_lang/claims_alternatives.json")).unwrap()
        );
    }
    #[test]
    fn test_oid4vp_example_multi_credentials_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![
                    CredentialQuery {
                        id: test_credential_query_id("pid"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/identity_credential".to_string()]
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("given_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("family_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("mdl"),
                        format: Format::MsoMdoc,
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.7367.1.mVRC".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.7367.1".to_string()),
                                    ClaimPathElement::String("vehicle_holder".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("first_name".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    }
                ],

                credential_sets: None
            },
            from_str::<DcqlQuery>(include_str!("../../tests/examples/query_lang/multi_credentials.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_complex_mdoc() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![
                    CredentialQuery {
                        id: test_credential_query_id("mdl-id"),
                        format: Format::MsoMdoc,
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.18013.5.1.mDL".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: Some("given_name".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: Some("family_name".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: Some("portrait".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("portrait".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("mdl-address"),
                        format: Format::MsoMdoc,
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.18013.5.1.mDL".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: Some("resident_address".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_address".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: Some("resident_country".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_country".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("photo_card-id"),
                        format: Format::MsoMdoc,
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.23220.photoid.1".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: Some("given_name".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("given_name".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: Some("family_name".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("family_name".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: Some("portrait".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("portrait".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("photo_card-address"),
                        format: Format::MsoMdoc,
                        multiple: None,
                        meta: Some(MetaTypes::MsoMdocMeta {
                            doctype_value: "org.iso.23220.photoid.1".to_string(),
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: Some("resident_address".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_address".to_string())
                                ]),
                                values: None
                            },
                            ClaimQuery {
                                id: Some("resident_country".to_string()),
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("org.iso.18013.5.1".to_string()),
                                    ClaimPathElement::String("resident_country".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    }
                ],
                credential_sets: Some(vec![
                    CredentialSetQuery {
                        options: vec![vec!["mdl-id".to_string()], vec!["photo_card-id".to_string()]],
                        required: Some(true),
                    },
                    CredentialSetQuery {
                        options: vec![vec!["mdl-address".to_string()], vec!["photo_card-address".to_string()]],
                        required: Some(false),
                    }
                ])
            },
            from_str::<DcqlQuery>(include_str!("../../tests/examples/query_lang/complex_mdoc.json")).unwrap()
        );
    }

    #[test]
    fn test_oid4vp_example_credentials_alternatives_json() {
        assert_eq!(
            DcqlQuery {
                credentials: vec![
                    CredentialQuery {
                        id: test_credential_query_id("pid"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/identity_credential".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("given_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("family_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("other_pid"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://othercredentials.example/pid".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("given_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("family_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![
                                    ClaimPathElement::String("address".to_string()),
                                    ClaimPathElement::String("street_address".to_string())
                                ]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("pid_reduced_cred_1"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://credentials.example.com/reduced_identity_credential".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("family_name".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("given_name".to_string())]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("pid_reduced_cred_2"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://cred.example/residence_credential".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("postal_code".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("locality".to_string())]),
                                values: None
                            },
                            ClaimQuery {
                                id: None,
                                path: test_claim_path(vec![ClaimPathElement::String("region".to_string())]),
                                values: None
                            }
                        ],
                        claim_sets: None
                    },
                    CredentialQuery {
                        id: test_credential_query_id("nice_to_have"),
                        format: Format::DcSdJwt,
                        multiple: None,
                        meta: Some(MetaTypes::SdJwtMeta {
                            vct_values: vec!["https://company.example/company_rewards".to_string()],
                        }),
                        trusted_authorities: None,
                        require_cryptographic_holder_binding: Some(true),
                        claims: vec![ClaimQuery {
                            id: None,
                            path: test_claim_path(vec![ClaimPathElement::String("rewards_number".to_string())]),
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
                        required: Some(true)
                    },
                    CredentialSetQuery {
                        options: vec![vec!["nice_to_have".to_string()]],
                        required: Some(false),
                    }
                ])
            },
            from_str::<DcqlQuery>(include_str!(
                "../../tests/examples/query_lang/credentials_alternatives.json"
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
    fn test_require_cryptographic_holder_binding() {
        let json = serde_json::json!({
            "id": "my_credential",
            "format": "dc+sd-jwt",
            "meta": {
                "vct_values": ["https://www.w3.org/2018/credentials/examples/v1#PersonalInformation"]
            },
            "claims": [
                {"path": ["credentialSubject", "familyName"]},
            ]
        });

        let credential_query: CredentialQuery =
            serde_json::from_value(json).expect("Failed to deserialize CredentialQuery");

        assert_eq!(credential_query.require_cryptographic_holder_binding, Some(true))
    }
    #[test]
    fn test_dcql_query() {
        let temporary = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: test_credential_query_id("my_credential"),
                format: Format::MsoMdoc,
                multiple: None,
                meta: Some(MetaTypes::SdJwtMeta {
                    vct_values: vec!["https://credentials.example.com/identity_credential".to_string()],
                }),
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
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
            id: test_credential_query_id("basho"),
            format: Format::LdpVc,
            multiple: None,
            meta: Some(MetaTypes::W3CFormatMeta {
                type_values: vec![vec!["https://example.com/credential".to_string()]],
            }),
            trusted_authorities: None,
            require_cryptographic_holder_binding: Some(true),
            claims: vec![ClaimQuery {
                id: None,
                path: test_claim_path(vec![ClaimPathElement::String("line_number".to_string())]),
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
            id: test_credential_query_id("robbie"),
            format: Format::DcSdJwt,
            multiple: None,
            meta: Some(MetaTypes::SdJwtMeta {
                vct_values: vec!["https://credentials.example.com/identity_credential".to_string()],
            }),
            trusted_authorities: None,
            require_cryptographic_holder_binding: Some(true),
            claims: vec![
                ClaimQuery {
                    id: Some("basho".to_string()),
                    path: test_claim_path(vec![ClaimPathElement::String("last_name".to_string())]),
                    values: None,
                },
                ClaimQuery {
                    id: Some("casho".to_string()),
                    path: test_claim_path(vec![ClaimPathElement::String("first_name".to_string())]),
                    values: Some(test_claim_values(vec![ClaimValue::String("Matsuo".to_string())])),
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
        assert!(parsed
            .as_object()
            .unwrap()
            .contains_key("require_cryptographic_holder_binding"));
    }
}
