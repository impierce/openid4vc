use crate::utils::predicates::not_empty;
use nutype::nutype;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A non-empty path identifying claims in JSON-based credentials.
#[nutype(validate(predicate = not_empty), derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, AsRef))]
pub struct ClaimPathPointer(Vec<ClaimPathElement>);

#[nutype(validate(predicate = not_empty), derive(Debug, Clone, Eq, PartialEq, Serialize, AsRef, Deserialize))]
pub struct ClaimValues(Vec<ClaimValue>);

/// A value selected by a Claim Path Pointer.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

/// One segment of a Claim Path Pointer.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum ClaimPathElement {
    /// To address a particular claim within an object, append the key (claim name) to the array.
    String(String),
    /// To address an element within an array, append the index to the array (as a non-negative, 0-based integer).
    Integer(u64),
    /// To address all elements within an array, append a null value to the array.
    Null,
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for ClaimPathPointer {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::Array::builder()
            .items(ClaimPathElement::schema())
            .min_items(Some(1))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for ClaimPathPointer {
    fn schemas(schemas: &mut Vec<(String, utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>)>) {
        schemas.push((
            <ClaimPathElement as utoipa::ToSchema>::name().into(),
            <ClaimPathElement as utoipa::PartialSchema>::schema(),
        ));
        <ClaimPathElement as utoipa::ToSchema>::schemas(schemas);
    }
}

impl ClaimPathPointer {
    /// As described in OID4VP - Section 7.1 for JSON-based credentials:
    /// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-semantics-for-json-based-cr>
    /// TODO: Add semantics for ISO Mdoc credential format.
    pub fn get_values_from_json(&self, json_data: &Value) -> Vec<Value> {
        let mut current_selections: Vec<&Value> = vec![json_data];
        for element in self.as_ref().iter() {
            let mut next_selections: Vec<&Value> = Vec::new();
            for selected_value in current_selections.drain(..) {
                match element {
                    ClaimPathElement::String(key) => {
                        if let Some(obj) = selected_value.as_object()
                            && let Some(value_found) = obj.get(key)
                        {
                            next_selections.push(value_found);
                        }
                    }
                    ClaimPathElement::Integer(index) => {
                        if let Some(arr) = selected_value.as_array()
                            && let Some(value_found) = arr.get(*index as usize)
                        {
                            next_selections.push(value_found);
                        }
                    }
                    ClaimPathElement::Null => {
                        if let Some(arr) = selected_value.as_array() {
                            for value_in_array in arr {
                                next_selections.push(value_in_array);
                            }
                        }
                    }
                }
            }
            current_selections = next_selections;
            if current_selections.is_empty() {
                break;
            }
        }
        current_selections.into_iter().cloned().collect()
    }
}

/// How the components of a claims path pointer address a credential: OpenID4VCI 1.0, Appendix C.1 for JSON-based
/// credentials, C.2 for ISO mdoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimPathSemantics {
    /// A non-negative integer is an array index (Appendix C.1).
    Json,
    /// A non-negative integer is a map key or an array index, depending on the data (Appendix C.2). Only `null`
    /// implies that a claim is an array.
    Mdoc,
}

/// A claims description that OpenID4VCI 1.0, Appendix B.3 rules out: "When a repeated or contradictory claim
/// description is provided, the processing MUST be aborted."
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsDescriptionError {
    /// "the same claim is addressed by two or more claims description objects in the `claims` array"
    #[error("Two or more claims descriptions address the same claim {path:?} (OpenID4VCI 1.0, Appendix B.3)")]
    RepeatedClaim { path: ClaimPathPointer },
    /// "a path that addresses a set of claims in an array (using `null` ...) and another object that uses a
    /// non-negative integer to address a specific claim in the same array"
    #[error(
        "The claims description {all:?} addresses all elements of an array that {index:?} addresses by index \
         (OpenID4VCI 1.0, Appendix B.3)"
    )]
    AllAndIndexInSameArray {
        /// The path with `null` at the array.
        all: ClaimPathPointer,
        /// The path with a non-negative integer at the same array.
        index: ClaimPathPointer,
    },
    /// "a claims description object indicating that a certain claim is an array (implied by using `null` or a
    /// non-negative integer in the path), and another object indicating that the same claim is an object (implied
    /// by using a string in the path)"
    #[error(
        "The claims description {array:?} implies a claim is an array, and {object:?} that it is an object \
         (OpenID4VCI 1.0, Appendix B.3)"
    )]
    ArrayAndObject {
        /// The path with `null` or a non-negative integer at the claim.
        array: ClaimPathPointer,
        /// The path with a string at the same claim.
        object: ClaimPathPointer,
    },
}

/// Checks the paths of the claims descriptions of one `claims` array against OpenID4VCI 1.0, Appendix B.3, and
/// returns the first rule broken. Each pair of paths is compared component by component; where they first differ,
/// the components before address the same claim:
///
/// - two equal paths address the same claim twice;
/// - `null` in one and a non-negative integer in the other address the same array both as a whole and by index;
/// - a string in one and `null` in the other make the same claim an object and an array. With
///   [`ClaimPathSemantics::Json`], so does a string next to a non-negative integer; with
///   [`ClaimPathSemantics::Mdoc`], both are map keys (Appendix C.2) and address different claims.
///
/// Any other difference addresses different claims. A path that is a prefix of another addresses a claim that
/// contains the other's, as `["address"]` and `["address", "street_address"]` in Section 12.2.4.
pub fn check_claims_description_paths<'a>(
    paths: impl IntoIterator<Item = &'a ClaimPathPointer>,
    semantics: ClaimPathSemantics,
) -> Result<(), ClaimsDescriptionError> {
    use ClaimPathElement::{Integer, Null, String};

    let paths: Vec<&ClaimPathPointer> = paths.into_iter().collect();
    for (position, first) in paths.iter().enumerate() {
        for second in &paths[position + 1..] {
            if first == second {
                return Err(ClaimsDescriptionError::RepeatedClaim { path: (*first).clone() });
            }
            let Some((a, b)) = first.as_ref().iter().zip(second.as_ref()).find(|(a, b)| a != b) else {
                // One path is a prefix of the other.
                continue;
            };
            match (a, b) {
                (Null, Integer(_)) => {
                    return Err(ClaimsDescriptionError::AllAndIndexInSameArray {
                        all: (*first).clone(),
                        index: (*second).clone(),
                    });
                }
                (Integer(_), Null) => {
                    return Err(ClaimsDescriptionError::AllAndIndexInSameArray {
                        all: (*second).clone(),
                        index: (*first).clone(),
                    });
                }
                (Null, String(_)) => {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: (*first).clone(),
                        object: (*second).clone(),
                    });
                }
                (String(_), Null) => {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: (*second).clone(),
                        object: (*first).clone(),
                    });
                }
                (Integer(_), String(_)) if semantics == ClaimPathSemantics::Json => {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: (*first).clone(),
                        object: (*second).clone(),
                    });
                }
                (String(_), Integer(_)) if semantics == ClaimPathSemantics::Json => {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: (*second).clone(),
                        object: (*first).clone(),
                    });
                }
                // Different keys or indexes, or with mdoc a string and an integer key of the same map.
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Example test case from: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-claims-path-pointer-example
    #[test]
    fn test_claim_path_pointer() {
        let example: serde_json::Value = json!({
            "name": "Arthur Dent",
            "address": {
                "street_address": "42 Market Street",
                "locality": "Milliways",
                "postal_code": "12345"
            },
            "degrees": [
                {
                    "type": "Bachelor of Science",
                    "university": "University of Betelgeuse"
                },
                {
                    "type": "Master of Science",
                    "university": "University of Betelgeuse"
                }
            ],
            "nationalities": ["British", "Betelgeusian"]
        });

        let claim_path_pointers = vec![
            ClaimPathPointer::try_new(vec![ClaimPathElement::String("name".to_string())]).unwrap(),
            ClaimPathPointer::try_new(vec![ClaimPathElement::String("address".to_string())]).unwrap(),
            ClaimPathPointer::try_new(vec![
                ClaimPathElement::String("address".to_string()),
                ClaimPathElement::String("street_address".to_string()),
            ])
            .unwrap(),
            ClaimPathPointer::try_new(vec![
                ClaimPathElement::String("degrees".to_string()),
                ClaimPathElement::Null,
                ClaimPathElement::String("type".to_string()),
            ])
            .unwrap(),
            ClaimPathPointer::try_new(vec![
                ClaimPathElement::String("nationalities".to_string()),
                ClaimPathElement::Integer(1),
            ])
            .unwrap(),
        ];

        let expected_values = vec![
            vec![json!("Arthur Dent")],
            vec![json!({
                "street_address": "42 Market Street",
                "locality": "Milliways",
                "postal_code": "12345"
            })],
            vec![json!("42 Market Street")],
            vec![json!("Bachelor of Science"), json!("Master of Science")],
            vec![json!("Betelgeusian")],
        ];

        let selected_values: Vec<Vec<Value>> = claim_path_pointers
            .into_iter()
            .map(|claim_path_pointer| claim_path_pointer.get_values_from_json(&example))
            .collect();

        assert_eq!(selected_values, expected_values);
    }

    /// A claims path pointer from JSON: strings, `null`s and non-negative integers.
    fn path(components: serde_json::Value) -> ClaimPathPointer {
        serde_json::from_value(components).unwrap()
    }

    fn check(paths: &[ClaimPathPointer], semantics: ClaimPathSemantics) -> Result<(), ClaimsDescriptionError> {
        check_claims_description_paths(paths, semantics)
    }

    #[test]
    fn claims_descriptions_of_objects_and_arrays_next_to_their_contents_are_valid() {
        let paths = [
            // Section 12.2.4: an object next to a claim in it.
            path(json!(["address"])),
            path(json!(["address", "street_address"])),
            // An array next to `null` paths into its items.
            path(json!(["Courses"])),
            path(json!(["Courses", null, "Code"])),
            path(json!(["Courses", null, "Country"])),
            path(json!(["Websites"])),
            path(json!(["Websites", null])),
            // Different elements of one array, and different keys of one object.
            path(json!(["nationalities", 0])),
            path(json!(["nationalities", 1])),
            path(json!(["degrees", 0, "type"])),
            path(json!(["degrees", 0, "university"])),
        ];
        assert_eq!(check(&paths, ClaimPathSemantics::Json), Ok(()));
        assert_eq!(check(&paths, ClaimPathSemantics::Mdoc), Ok(()));
    }

    /// The claims of the training record example in impierce/openid4vc#235.
    #[test]
    fn the_training_record_of_the_issue_is_valid() {
        let paths = [
            path(json!(["credentialSubject", "Trainee"])),
            path(json!(["credentialSubject", "Trainee", "Full name"])),
            path(json!(["credentialSubject", "Trainee", "Nationality"])),
            path(json!(["credentialSubject", "Skills"])),
            path(json!(["credentialSubject", "Websites"])),
            path(json!(["credentialSubject", "Websites", null])),
            path(json!(["credentialSubject", "Courses"])),
            path(json!(["credentialSubject", "Courses", null, "Code"])),
            path(json!(["credentialSubject", "Courses", null, "Country"])),
        ];
        assert_eq!(check(&paths, ClaimPathSemantics::Json), Ok(()));
    }

    #[test]
    fn the_same_claim_addressed_twice_is_refused() {
        let paths = [
            path(json!(["address", "street_address"])),
            path(json!(["name"])),
            path(json!(["address", "street_address"])),
        ];
        let error = check(&paths, ClaimPathSemantics::Json).unwrap_err();
        assert_eq!(
            error,
            ClaimsDescriptionError::RepeatedClaim {
                path: path(json!(["address", "street_address"]))
            }
        );
        assert!(error.to_string().contains("address the same claim"), "{error}");
    }

    #[test]
    fn null_and_an_index_for_the_same_array_are_refused() {
        for (first, second) in [
            (json!(["degrees", null, "type"]), json!(["degrees", 1, "type"])),
            (json!(["nationalities", 0]), json!(["nationalities", null])),
            (json!(["degrees", null, "type"]), json!(["degrees", 0, "university"])),
        ] {
            for semantics in [ClaimPathSemantics::Json, ClaimPathSemantics::Mdoc] {
                let error = check(&[path(first.clone()), path(second.clone())], semantics).unwrap_err();
                assert!(
                    matches!(error, ClaimsDescriptionError::AllAndIndexInSameArray { .. }),
                    "{first} and {second}: {error}"
                );
            }
        }
        assert_eq!(
            check(
                &[path(json!(["nationalities", 0])), path(json!(["nationalities", null]))],
                ClaimPathSemantics::Json
            ),
            Err(ClaimsDescriptionError::AllAndIndexInSameArray {
                all: path(json!(["nationalities", null])),
                index: path(json!(["nationalities", 0])),
            })
        );
    }

    #[test]
    fn a_claim_that_is_an_array_in_one_description_and_an_object_in_another_is_refused() {
        // `null` implies an array for every format.
        for semantics in [ClaimPathSemantics::Json, ClaimPathSemantics::Mdoc] {
            assert_eq!(
                check(
                    &[
                        path(json!(["address", "street_address"])),
                        path(json!(["address", null]))
                    ],
                    semantics
                ),
                Err(ClaimsDescriptionError::ArrayAndObject {
                    array: path(json!(["address", null])),
                    object: path(json!(["address", "street_address"])),
                })
            );
        }
        // For JSON-based credentials, an integer is an array index (Appendix C.1).
        let error = check(
            &[path(json!(["degrees", 0])), path(json!(["degrees", "type"]))],
            ClaimPathSemantics::Json,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ClaimsDescriptionError::ArrayAndObject {
                array: path(json!(["degrees", 0])),
                object: path(json!(["degrees", "type"])),
            }
        );
        assert!(error.to_string().contains("is an array"), "{error}");
    }

    /// In an ISO mdoc, a non-negative integer can be a map key (Appendix C.2), so it implies no array next to a
    /// string key of the same map.
    #[test]
    fn with_mdoc_an_integer_and_a_string_are_keys_of_the_same_map() {
        let paths = [
            path(json!(["org.iso.18013.5.1", "driving_privileges", 1])),
            path(json!(["org.iso.18013.5.1", "driving_privileges", "codes"])),
        ];
        assert_eq!(check(&paths, ClaimPathSemantics::Mdoc), Ok(()));
        assert!(matches!(
            check(&paths, ClaimPathSemantics::Json),
            Err(ClaimsDescriptionError::ArrayAndObject { .. })
        ));
    }
}
