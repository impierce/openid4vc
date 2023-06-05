use crate::PresentationDefinition;
use jsonpath_lib as jsonpath;
use jsonschema::JSONSchema;

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

/// Input Evaluation as described in section [8. Input
/// Evaluation](https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation) of the DIF
/// Presentation Exchange specification.
pub fn evaluate_input(presentation_definition: &PresentationDefinition, value: &serde_json::Value) -> bool {
    // For each Input Descriptor in the input_descriptors array of a [`PresentationDefinition`], a conformant consumer
    // compares each candidate input (JWT, Verifiable Credential, etc.) it holds to determine whether there is a match.
    let selector = &mut jsonpath::selector(value);
    // If the `constraints` property of the [`InputDescriptor`] is present, and it contains a `fields` property with
    // one or more fields objects, evaluate each fields object against the candidate input as described in the
    // following subsequence.
    presentation_definition
        .input_descriptors()
        .iter()
        // Accept the candidate input if every fields object yields a [`FieldQueryResult`]; else, reject.
        .all(|input_descriptor| {
            input_descriptor
                .constraints()
                .fields()
                .as_ref()
                .map(|fields| {
                    let results: Vec<FieldQueryResult> = fields
                        .iter()
                        .map(|field| {
                            let filter = field
                                .filter()
                                .as_ref()
                                .map(JSONSchema::compile)
                                .transpose()
                                .ok()
                                .flatten();

                            // For each JSONPath expression in the `path` array (incrementing from the 0-index),
                            // evaluate the JSONPath expression against the candidate input and repeat the following
                            // subsequence on the result.
                            field
                                .path()
                                .iter()
                                // Repeat until a Field Query Result is found, or the path array elements are exhausted:
                                .find_map(|path| {
                                    // If the result returned no JSONPath match, skip to the next path array element.
                                    // Else, evaluate the first JSONPath match (candidate) as follows:
                                    selector(path).ok().and_then(|values| {
                                        values.into_iter().find_map(|result| {
                                            // If the fields object has no `filter`, or if candidate validates against
                                            // the JSON Schema descriptor specified in `filter`, then:
                                            filter
                                                .as_ref()
                                                .map(|filter| filter.is_valid(result))
                                                .unwrap_or(true)
                                                // set Field Query Result to be candidate
                                                .then(|| FieldQueryResult::Some {
                                                    value: result.to_owned(),
                                                    path: path.to_owned(),
                                                })
                                            // Else, skip to the next `path` array element.
                                        })
                                    })
                                })
                                // If no value is located for any of the specified `path` queries, and the fields
                                // object DOES NOT contain the `optional` property or it is set to `false`, reject the
                                // field as invalid. If no value is located for any of the specified `path` queries and
                                // the fields object DOES contain the `optional` property set to the value `true`,
                                // treat the field as valid and proceed to the next fields object.
                                .or_else(|| field.optional().and_then(|opt| opt.then(|| FieldQueryResult::None)))
                                .unwrap_or(FieldQueryResult::Invalid)
                        })
                        .collect();
                    results.iter().all(FieldQueryResult::is_valid)
                })
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        presentation_definition::{Constraints, Field},
        InputDescriptor,
    };
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

    fn presentation_definition(constraints: Constraints) -> PresentationDefinition {
        PresentationDefinition {
            id: "test_presentation_definition".to_string(),
            input_descriptors: vec![InputDescriptor {
                id: "test_input_descriptor".to_string(),
                name: None,
                purpose: None,
                format: None,
                constraints,
                schema: None,
            }],
            name: None,
            purpose: None,
            format: None,
        }
    }

    #[test]
    fn test_constraints() {
        let credential = json_example::<serde_json::Value>("./tests/examples/credentials/jwt_vc.json");

        // Has NO fields.
        assert!(!evaluate_input(
            &presentation_definition(Constraints::default()),
            &credential
        ));

        // Has ONE VALID field.
        assert!(evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.type".to_string()],
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // // Has ONE INVALID field.
        assert!(!evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.foo".to_string()],
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // First field is INVALID.
        assert!(!evaluate_input(
            &presentation_definition(Constraints {
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
            }),
            &credential
        ));

        // Second field is INVALID.
        assert!(!evaluate_input(
            &presentation_definition(Constraints {
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
            }),
            &credential
        ));

        // Second field is INVALID but optional.
        assert!(evaluate_input(
            &presentation_definition(Constraints {
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
            }),
            &credential
        ));
    }

    #[test]
    fn test_field() {
        let credential = json_example::<serde_json::Value>("./tests/examples/credentials/jwt_vc.json");

        // Has NO path.
        assert!(!evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field::default()]),
                ..Default::default()
            }),
            &credential
        ));

        // Has ONE path.
        assert!(evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.type".to_string()],
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // Has TWO paths. First is NO match, second is a match without filter.
        assert!(evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.foo".to_string(), "$.vc.type".to_string()],
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // Has TWO paths. First is a match, with filter.
        assert!(evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.type".to_string(), "$.vc.foo".to_string()],
                    filter: Some(serde_json::json!({
                        "type": "array",
                        "contains": {
                            "const": "IDCredential"
                        }
                    })),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // Has ONE paths. With non-matching filter.
        assert!(!evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.type".to_string()],
                    filter: Some(serde_json::json!({
                        "type": "array",
                        "contains": {
                            "const": "Foo"
                        }
                    })),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // Has ONE path. With non-matching filter. Is optional
        assert!(evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.type".to_string()],
                    filter: Some(serde_json::json!({
                        "type": "array",
                        "contains": {
                            "const": "Foo"
                        }
                    })),
                    optional: Some(true),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // Has ONE path, which does not exist. Is optional
        assert!(evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.foo".to_string()],
                    optional: Some(true),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));

        // Has ONE path, which does not exist. Is NOT optional (explicitly).
        assert!(!evaluate_input(
            &presentation_definition(Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.vc.foo".to_string()],
                    optional: Some(false),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            &credential
        ));
    }
}
