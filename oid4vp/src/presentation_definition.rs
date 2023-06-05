use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

// TODO: replace with identity_credential once this issue is resolved:
// https://github.com/iotaledger/identity.rs/issues/1151
#[skip_serializing_none]
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: Option<String>,
    pub type_: Vec<String>,
    pub verifiable_credential: Option<Vec<String>>,
    pub holder: Option<String>,
}

impl Default for VerifiablePresentation {
    fn default() -> Self {
        VerifiablePresentation {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: None,
            type_: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: None,
            holder: None,
        }
    }
}

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
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
#[derive(Deserialize, Debug, Getters, PartialEq, Clone, Serialize)]
pub struct InputDescriptor {
    // Must not conflict with other input descriptors.
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
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimFormatProperty {
    Alg(Vec<serde_json::Value>),
    ProofType(Vec<serde_json::Value>),
}

#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
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
                        ClaimFormatProperty::ProofType(vec![serde_json::json!("CLSignature2019")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/pd_ac_vc_sd.json")
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
                        ClaimFormatProperty::ProofType(vec![serde_json::json!("CLSignature2019")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/pd_ac_vc.json")
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
                        ClaimFormatProperty::ProofType(vec![serde_json::json!("JsonWebSignature2020")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/pd_jwt_vc.json")
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
                        ClaimFormatProperty::ProofType(vec![serde_json::json!("Ed25519Signature2018")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/pd_ldp_vc.json")
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
                        ClaimFormatProperty::Alg(vec![serde_json::json!("EdDSA"), serde_json::json!("ES256")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/pd_mdl_iso_cbor.json")
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
                        ClaimFormatProperty::ProofType(vec![serde_json::json!("Ed25519Signature2018")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/vp_token_type_and_claims.json")
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
                        ClaimFormatProperty::ProofType(vec![serde_json::json!("Ed25519Signature2018")])
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
            json_example::<PresentationDefinition>("./tests/examples/request/vp_token_type_only.json")
        );
    }
}
