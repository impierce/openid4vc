use getset::Getters;
use jsonpath_lib as jsonpath;
use jsonschema::JSONSchema;
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
    id: String,
    // All inputs listed in the `input_descriptors` array are required for submission, unless otherwise specified by a
    // Feature.
    #[getset(get = "pub")]
    input_descriptors: Vec<InputDescriptor>,
    name: Option<String>,
    purpose: Option<String>,
    format: Option<HashMap<ClaimFormatDesignation, ClaimFormatProperty>>,
}

/// As specified in https://identity.foundation/presentation-exchange/#input-descriptor-object.
/// All input descriptors MUST be satisfied, unless otherwise specified by a Feature.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Getters, PartialEq, Clone, Serialize)]
pub struct InputDescriptor {
    // Must not conflict with other input descriptors.
    id: String,
    name: Option<String>,
    purpose: Option<String>,
    format: Option<HashMap<ClaimFormatDesignation, ClaimFormatProperty>>,
    #[getset(get = "pub")]
    constraints: Constraints,
    schema: Option<String>,
}

impl InputDescriptor {
    pub fn evaluate<'a, F>(&self, selector: &mut F) -> bool
    where
        F: FnMut(&str) -> Result<Vec<&'a serde_json::Value>, jsonpath::JsonPathError>,
    {
        self.constraints.evaluate(selector)
    }
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
    pub(self) fields: Option<Vec<Field>>,
    // Omission of the `limit_disclosure` property indicates the Conforment Consumer MAY submit a response that contains
    // more than the data described in the `fields` array.
    #[getset(get = "pub")]
    pub(self) limit_disclosure: Option<LimitDisclosure>,
}

impl Constraints {
    fn evaluate<'a, F>(&self, selector: &mut F) -> bool
    where
        F: FnMut(&str) -> Result<Vec<&'a serde_json::Value>, jsonpath::JsonPathError>,
    {
        self.fields()
            .as_ref()
            .map(|fields| {
                let results: Vec<FieldQueryResult> = fields.iter().map(|field| field.evaluate(selector)).collect();
                results.iter().all(FieldQueryResult::is_valid)
            })
            .unwrap_or(false)
    }
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
    path: Vec<String>,
    id: Option<String>,
    purpose: Option<String>,
    name: Option<String>,
    #[getset(get = "pub")]
    filter: Option<serde_json::Value>,
    // TODO: check default behaviour
    #[getset(get = "pub")]
    optional: Option<bool>,
}

impl Field {
    fn evaluate<'a, F>(&self, selector: &mut F) -> FieldQueryResult
    where
        F: FnMut(&str) -> Result<Vec<&'a serde_json::Value>, jsonpath::JsonPathError>,
    {
        let filter = self
            .filter()
            .as_ref()
            .map(JSONSchema::compile)
            .transpose()
            .ok()
            .flatten();

        self.path()
            .iter()
            .find_map(|path| {
                selector(path).unwrap().into_iter().find_map(|result| {
                    filter
                        .as_ref()
                        .map(|filter| filter.is_valid(result))
                        .unwrap_or(true)
                        .then(|| FieldQueryResult::Some {
                            value: result.to_owned(),
                            path: path.to_owned(),
                        })
                })
            })
            .or_else(|| self.optional().and_then(|opt| opt.then(|| FieldQueryResult::None)))
            .unwrap_or(FieldQueryResult::Invalid)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldQueryResult {
    Some { value: serde_json::Value, path: String },
    None,
    Invalid,
}

impl FieldQueryResult {
    pub fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    pub fn is_invalid(&self) -> bool {
        *self == FieldQueryResult::Invalid
    }
}

pub fn input_evaluation(presentation_definition: &PresentationDefinition, value: &serde_json::Value) -> bool {
    // For each Input Descriptor in the input_descriptors array of a Presentation Definition, a conformant consumer
    // compares each candidate input (JWT, Verifiable Credential, etc.) it holds to determine whether there is a match.
    presentation_definition
        .input_descriptors()
        .iter()
        .all(|input_descriptor| input_descriptor.evaluate(&mut jsonpath::selector(&value)))
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
            json_example::<PresentationDefinition>("./examples/request/vp_token_type_only.json")
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
            json_example::<PresentationDefinition>("./examples/request/vp_token_type_and_claims.json")
        );
    }

    #[test]
    fn test_constraints() {
        let json = json_example::<serde_json::Value>("./examples/credentials/jwt_vc.json");
        let selector = &mut jsonpath::selector(&json);

        // Has NO fields.
        let constraints = Constraints::default();
        assert!(!constraints.evaluate(selector));

        // Has ONE VALID field.
        let constraints = Constraints {
            fields: Some(vec![Field {
                path: vec!["$.vc.type".to_string()],
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert!(constraints.evaluate(selector));

        // Has ONE INVALID field.
        let constraints = Constraints {
            fields: Some(vec![Field {
                path: vec!["$.vc.foo".to_string()],
                ..Default::default()
            }]),
            ..Default::default()
        };
        assert!(!constraints.evaluate(selector));

        // First field is INVALID.
        let constraints = Constraints {
            fields: Some(vec![
                Field {
                    path: vec!["$.vc.foo".to_string()],
                    ..Default::default()
                },
                Field {
                    path: vec!["$.vc.type".to_string()],
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        assert!(!constraints.evaluate(selector));

        // Second field is INVALID.
        let constraints = Constraints {
            fields: Some(vec![
                Field {
                    path: vec!["$.vc.type".to_string()],
                    ..Default::default()
                },
                Field {
                    path: vec!["$.vc.foo".to_string()],
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        assert!(!constraints.evaluate(selector));

        // Second field is INVALID.
        let constraints = Constraints {
            fields: Some(vec![
                Field {
                    path: vec!["$.vc.type".to_string()],
                    ..Default::default()
                },
                Field {
                    path: vec!["$.vc.foo".to_string()],
                    optional: Some(true),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        assert!(constraints.evaluate(selector));
    }

    #[test]
    fn test_field() {
        let json = json_example::<serde_json::Value>("./examples/credentials/jwt_vc.json");
        let selector = &mut jsonpath::selector(&json);

        // Has NO path.
        let field = Field::default();
        assert!(matches!(field.evaluate(selector), FieldQueryResult::Invalid));

        // Has ONE path.
        let field = Field {
            path: vec!["$.vc.type".to_string()],
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::Some { .. }));

        // Has TWO paths. First is NO match, second is a match without filter.
        let field = Field {
            path: vec!["$.vc.foo".to_string(), "$.vc.type".to_string()],
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::Some { .. }));

        // Has TWO paths. First is a match, with filter.
        let field = Field {
            path: vec!["$.vc.type".to_string(), "$.vc.foo".to_string()],
            filter: Some(serde_json::json!({
                "type": "array",
                "contains": {
                    "const": "IDCredential"
                }
            })),
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::Some { .. }));

        // Has ONE paths. With non-matching filter.
        let field = Field {
            path: vec!["$.vc.type".to_string()],
            filter: Some(serde_json::json!({
                "type": "array",
                "contains": {
                    "const": "Foo"
                }
            })),
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::Invalid));

        // Has ONE path. With non-matching filter. Is optional
        let field = Field {
            path: vec!["$.vc.type".to_string()],
            filter: Some(serde_json::json!({
                "type": "array",
                "contains": {
                    "const": "Foo"
                }
            })),
            optional: Some(true),
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::None));

        // Has ONE path, which does not exist. Is optional
        let field = Field {
            path: vec!["$.vc.foo".to_string()],
            optional: Some(true),
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::None));

        // Has ONE path, which does not exist. Is NOT optional (explicitly).
        let field = Field {
            path: vec!["$.vc.foo".to_string()],
            optional: Some(false),
            ..Default::default()
        };
        assert!(matches!(field.evaluate(selector), FieldQueryResult::Invalid));
    }
}
