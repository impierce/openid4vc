use crate::utils::predicates::not_empty;
use nutype::nutype;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

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
    /// Checks that this path can address a claim in a credential with these semantics, before any credential is
    /// at hand:
    ///
    /// - [`ClaimPathSemantics::Json`]: it starts with a string, a key of the top-level object (Appendix C.1.1);
    /// - [`ClaimPathSemantics::Mdoc`]: it starts with two strings, the namespace and the data element identifier
    ///   (Appendix C.2);
    /// - [`ClaimPathSemantics::Unknown`]: nothing is checked.
    pub fn check_shape(&self, semantics: ClaimPathSemantics) -> Result<(), ClaimPathError> {
        let components = self.as_ref();
        match semantics {
            ClaimPathSemantics::Json => match components.first() {
                Some(ClaimPathElement::String(_)) => Ok(()),
                _ => Err(ClaimPathError::JsonRootAsArray { path: self.clone() }),
            },
            ClaimPathSemantics::Mdoc => match components.as_slice() {
                [ClaimPathElement::String(_), ClaimPathElement::String(_), ..] => Ok(()),
                _ => Err(ClaimPathError::NoMdocNamespaceAndDataElement { path: self.clone() }),
            },
            ClaimPathSemantics::Unknown => Ok(()),
        }
    }

    /// Processes this path on a JSON-based credential and returns the selected claims (OID4VP 1.0, Section 7.1.1;
    /// OpenID4VCI 1.0, Appendix C.1.1). Processing starts at `json_data`, the top-level object of the credential.
    ///
    /// A key that an object does not have, or an index past the end of an array, removes that element from the
    /// selection. Processing is aborted with an error when:
    ///
    /// - a string is applied to an element that is not an object ([`ClaimPathProcessingError::NotAnObject`]);
    /// - `null` or a non-negative integer is applied to an element that is not an array
    ///   ([`ClaimPathProcessingError::NotAnArray`]);
    /// - nothing is left selected ([`ClaimPathProcessingError::NothingSelected`]), so the claim is not in the
    ///   credential.
    ///
    /// TODO: Add semantics for ISO Mdoc credential format.
    pub fn get_values_from_json(&self, json_data: &Value) -> Result<Vec<Value>, ClaimPathProcessingError> {
        let mut selection: Vec<&Value> = vec![json_data];
        for (index, component) in self.as_ref().iter().enumerate() {
            let mut next_selection: Vec<&Value> = Vec::new();
            for selected in selection {
                match component {
                    ClaimPathElement::String(key) => {
                        let object = selected
                            .as_object()
                            .ok_or_else(|| ClaimPathProcessingError::NotAnObject {
                                path: self.clone(),
                                index,
                            })?;
                        next_selection.extend(object.get(key));
                    }
                    ClaimPathElement::Integer(array_index) => {
                        let array = selected
                            .as_array()
                            .ok_or_else(|| ClaimPathProcessingError::NotAnArray {
                                path: self.clone(),
                                index,
                            })?;
                        next_selection.extend(usize::try_from(*array_index).ok().and_then(|i| array.get(i)));
                    }
                    ClaimPathElement::Null => {
                        let array = selected
                            .as_array()
                            .ok_or_else(|| ClaimPathProcessingError::NotAnArray {
                                path: self.clone(),
                                index,
                            })?;
                        next_selection.extend(array);
                    }
                }
            }
            selection = next_selection;
            // Nothing that follows can select anything again.
            if selection.is_empty() {
                return Err(ClaimPathProcessingError::NothingSelected { path: self.clone() });
            }
        }
        Ok(selection.into_iter().cloned().collect())
    }
}

/// How the components of a claims path pointer address a credential: OpenID4VCI 1.0, Appendix C.1 for JSON-based
/// credentials, C.2 for ISO mdoc, neither for a format whose data model is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimPathSemantics {
    /// A non-negative integer is an array index, and a path starts at the top-level object of the credential, so
    /// with a string (Appendix C.1).
    Json,
    /// A non-negative integer is a map key or an array index, depending on the data (Appendix C.2). Only `null`
    /// implies that a claim is an array.
    ///
    /// Appendix B.3 says a claim is an array if a path has "`null` or a non-negative integer" at it, with no
    /// exception for ISO mdoc. Taken literally, that would refuse `["ns", "element", 1]` next to
    /// `["ns", "element", "key"]`, which Appendix C.2 allows: both are keys of the same map. For ISO mdoc this
    /// follows C.2, which says what an integer means in an ISO mdoc path.
    ///
    /// A path starts with the namespace and the data element identifier, both strings (Appendix C.2).
    Mdoc,
    /// The data model of the format is not known. Appendix B.3 is applied as it reads: `null` or a non-negative
    /// integer implies an array. Nothing is assumed about where a path starts.
    Unknown,
}

/// A claims path pointer that cannot address a claim in a credential (OpenID4VCI 1.0, Appendix C), whatever the
/// credential contains.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimPathError {
    /// "A claims path pointer into an ISO mdoc always contains at least two path components of type string", the
    /// namespace and the data element identifier (Appendix C.2).
    #[error(
        "The claims path pointer {path:?} does not start with an ISO mdoc namespace and data element identifier, \
         both strings (OpenID4VCI 1.0, Appendix C.2)"
    )]
    NoMdocNamespaceAndDataElement { path: ClaimPathPointer },
    /// Processing starts at "the top-level object of the JSON structure representing the claims in the
    /// Credential", and `null` or a non-negative integer on an element that is not an array aborts it
    /// (Appendix C.1.1).
    #[error(
        "The claims path pointer {path:?} addresses the top-level object of a JSON-based credential as an array \
         (OpenID4VCI 1.0, Appendix C.1.1)"
    )]
    JsonRootAsArray { path: ClaimPathPointer },
}

/// Why processing a claims path pointer on a JSON-based credential was aborted (OID4VP 1.0, Section 7.1.1;
/// OpenID4VCI 1.0, Appendix C.1.1). `index` is the position of the component that aborted it, from 0.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimPathProcessingError {
    /// "If the component is a string, [...] If any of the currently selected element(s) is not an object, abort
    /// processing and return an error."
    #[error(
        "Component {index} of the claims path pointer {path:?} is a key, but a selected element is not an object \
         (OID4VP 1.0, Section 7.1.1)"
    )]
    NotAnObject { path: ClaimPathPointer, index: usize },
    /// "If the component is null, [...] If any of the currently selected element(s) is not an array, abort
    /// processing and return an error.", and the same for a non-negative integer.
    #[error(
        "Component {index} of the claims path pointer {path:?} is `null` or an index, but a selected element is \
         not an array (OID4VP 1.0, Section 7.1.1)"
    )]
    NotAnArray { path: ClaimPathPointer, index: usize },
    /// "If the set of elements currently selected is empty, abort processing and return an error." The claim is
    /// not in the credential.
    #[error("The claims path pointer {path:?} selects nothing (OID4VP 1.0, Section 7.1.1)")]
    NothingSelected { path: ClaimPathPointer },
}

/// A claims description that OpenID4VCI 1.0, Appendix B.3 rules out: "When a repeated or contradictory claim
/// description is provided, the processing MUST be aborted." Or a path that cannot address a claim at all
/// (Appendix C).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// A path that cannot address a claim at all ([`ClaimPathPointer::check_shape`]).
    #[error(transparent)]
    InvalidPath(#[from] ClaimPathError),
}

/// Checks the paths of the claims descriptions of one `claims` array against OpenID4VCI 1.0, Appendix B.3, and
/// returns a rule broken. Each path is first checked on its own with [`ClaimPathPointer::check_shape`]. Two paths
/// are compared where they first differ; the components before address the same claim:
///
/// - two equal paths address the same claim twice;
/// - `null` in one and a non-negative integer in the other address the same array both as a whole and by index;
/// - a string in one and `null` in the other make the same claim an object and an array. With
///   [`ClaimPathSemantics::Json`] and [`ClaimPathSemantics::Unknown`], so does a string next to a non-negative
///   integer; with [`ClaimPathSemantics::Mdoc`], both are map keys (Appendix C.2) and address different claims.
///
/// Any other difference addresses different claims. A path that is a prefix of another addresses a claim that
/// contains the other's, as `["address"]` and `["address", "street_address"]` in Section 12.2.4.
///
/// The paths are put in a tree of the claims they address, so the time taken grows with the total length of the
/// paths, not with the square of their number: a Wallet can run this on the metadata of any Credential Issuer.
pub fn check_claims_description_paths<'a>(
    paths: impl IntoIterator<Item = &'a ClaimPathPointer>,
    semantics: ClaimPathSemantics,
) -> Result<(), ClaimsDescriptionError> {
    // The claims the paths address or pass through, the root first, and the claim each component selects, by the
    // index of the claim it is applied to. Flat rather than nested, so that neither building nor dropping the tree
    // recurses: a path can have any number of components.
    let mut claims = vec![AddressedClaim::default()];
    let mut contents: HashMap<(usize, ComponentKey<'a>), usize> = HashMap::new();
    for path in paths {
        path.check_shape(semantics)?;
        let mut claim = 0;
        for component in path.as_ref() {
            claim = match contents.entry((claim, ComponentKey::from(component))) {
                Entry::Occupied(entry) => *entry.get(),
                Entry::Vacant(entry) => {
                    claims[claim].check_new_component(component, path, semantics)?;
                    claims.push(AddressedClaim::default());
                    *entry.insert(claims.len() - 1)
                }
            };
        }
        if claims[claim].addressed {
            return Err(ClaimsDescriptionError::RepeatedClaim { path: path.clone() });
        }
        claims[claim].addressed = true;
    }
    Ok(())
}

/// A claim that one or more of the paths checked by [`check_claims_description_paths`] address or pass through.
#[derive(Default)]
struct AddressedClaim<'a> {
    /// A path ends at this claim.
    addressed: bool,
    /// The first path with `null` at this claim.
    first_null: Option<&'a ClaimPathPointer>,
    /// The first path with a non-negative integer at this claim.
    first_integer: Option<&'a ClaimPathPointer>,
    /// The first path with a string at this claim.
    first_string: Option<&'a ClaimPathPointer>,
}

impl<'a> AddressedClaim<'a> {
    /// Checks a component that no earlier path has at this claim against those that earlier paths have, then
    /// records it. Two paths that first differ here contradict each other if their components do.
    fn check_new_component(
        &mut self,
        component: &ClaimPathElement,
        path: &'a ClaimPathPointer,
        semantics: ClaimPathSemantics,
    ) -> Result<(), ClaimsDescriptionError> {
        // Only with ISO mdoc can a non-negative integer be a map key (Appendix C.2).
        let integer_is_index = semantics != ClaimPathSemantics::Mdoc;
        match component {
            ClaimPathElement::Null => {
                if let Some(index) = self.first_integer {
                    return Err(ClaimsDescriptionError::AllAndIndexInSameArray {
                        all: path.clone(),
                        index: index.clone(),
                    });
                }
                if let Some(object) = self.first_string {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: path.clone(),
                        object: object.clone(),
                    });
                }
                self.first_null.get_or_insert(path);
            }
            ClaimPathElement::Integer(_) => {
                if let Some(all) = self.first_null {
                    return Err(ClaimsDescriptionError::AllAndIndexInSameArray {
                        all: all.clone(),
                        index: path.clone(),
                    });
                }
                if let Some(object) = self.first_string.filter(|_| integer_is_index) {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: path.clone(),
                        object: object.clone(),
                    });
                }
                self.first_integer.get_or_insert(path);
            }
            ClaimPathElement::String(_) => {
                if let Some(array) = self.first_null.or(self.first_integer.filter(|_| integer_is_index)) {
                    return Err(ClaimsDescriptionError::ArrayAndObject {
                        array: array.clone(),
                        object: path.clone(),
                    });
                }
                self.first_string.get_or_insert(path);
            }
        }
        Ok(())
    }
}

/// A component of a path as the key of the claim it selects.
#[derive(PartialEq, Eq, Hash)]
enum ComponentKey<'a> {
    Null,
    Integer(u64),
    String(&'a str),
}

impl<'a> From<&'a ClaimPathElement> for ComponentKey<'a> {
    fn from(component: &'a ClaimPathElement) -> Self {
        match component {
            ClaimPathElement::Null => ComponentKey::Null,
            ClaimPathElement::Integer(index) => ComponentKey::Integer(*index),
            ClaimPathElement::String(key) => ComponentKey::String(key),
        }
    }
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
            .map(|claim_path_pointer| claim_path_pointer.get_values_from_json(&example).unwrap())
            .collect();

        assert_eq!(selected_values, expected_values);
    }

    /// The credential of OID4VP 1.0, Section 7.3 (OpenID4VCI 1.0, Appendix C.3).
    fn arthur_dent() -> Value {
        json!({
            "name": "Arthur Dent",
            "address": {
                "street_address": "42 Market Street",
                "locality": "Milliways",
                "postal_code": "12345"
            },
            "degrees": [
                { "type": "Bachelor of Science", "university": "University of Betelgeuse" },
                { "type": "Master of Science", "university": "University of Betelgeuse" }
            ],
            "nationalities": ["British", "Betelgeusian"]
        })
    }

    #[test]
    fn a_missing_key_or_index_only_removes_that_element_from_the_selection() {
        let mut credential = arthur_dent();
        credential["degrees"][1].as_object_mut().unwrap().remove("university");
        assert_eq!(
            path(json!(["degrees", null, "university"])).get_values_from_json(&credential),
            Ok(vec![json!("University of Betelgeuse")])
        );
        // An index past the end of one array, but not of another.
        let credential = json!({ "lists": [["a"], ["b", "c"]] });
        assert_eq!(
            path(json!(["lists", null, 1])).get_values_from_json(&credential),
            Ok(vec![json!("c")])
        );
    }

    #[test]
    fn a_claim_that_is_not_in_the_credential_selects_nothing() {
        for components in [
            json!(["birthdate"]),
            json!(["address", "country"]),
            json!(["nationalities", 2]),
            json!(["degrees", null, "grade"]),
        ] {
            let path = path(components);
            assert_eq!(
                path.get_values_from_json(&arthur_dent()),
                Err(ClaimPathProcessingError::NothingSelected { path: path.clone() })
            );
        }
        // `null` on an empty array selects nothing either.
        let path = path(json!(["degrees", null]));
        assert_eq!(
            path.get_values_from_json(&json!({ "degrees": [] })),
            Err(ClaimPathProcessingError::NothingSelected { path: path.clone() })
        );
    }

    #[test]
    fn a_key_on_an_element_that_is_not_an_object_aborts_processing() {
        for (components, index) in [
            (json!(["name", "first"]), 1),
            (json!(["nationalities", null, "code"]), 2),
            (json!(["degrees", "type"]), 1),
        ] {
            let path = path(components);
            assert_eq!(
                path.get_values_from_json(&arthur_dent()),
                Err(ClaimPathProcessingError::NotAnObject {
                    path: path.clone(),
                    index
                })
            );
        }
        // One element that is not an object is enough, even if another has the key.
        let path = path(json!(["degrees", null, "type"]));
        let error = path
            .get_values_from_json(&json!({ "degrees": [{ "type": "BSc" }, "MSc"] }))
            .unwrap_err();
        assert_eq!(
            error,
            ClaimPathProcessingError::NotAnObject {
                path: path.clone(),
                index: 2
            }
        );
        assert!(error.to_string().contains("Section 7.1.1"), "{error}");
    }

    #[test]
    fn null_or_an_index_on_an_element_that_is_not_an_array_aborts_processing() {
        for (components, index) in [
            (json!([null]), 0),
            (json!([0]), 0),
            (json!(["address", null]), 1),
            (json!(["name", 0]), 1),
            (json!(["degrees", null, null]), 2),
        ] {
            let path = path(components);
            assert_eq!(
                path.get_values_from_json(&arthur_dent()),
                Err(ClaimPathProcessingError::NotAnArray {
                    path: path.clone(),
                    index
                })
            );
        }
    }

    /// A claims path pointer from JSON: strings, `null`s and non-negative integers.
    fn path(components: serde_json::Value) -> ClaimPathPointer {
        serde_json::from_value(components).unwrap()
    }

    fn check(paths: &[ClaimPathPointer], semantics: ClaimPathSemantics) -> Result<(), ClaimsDescriptionError> {
        check_claims_description_paths(paths, semantics)
    }

    /// A path for these semantics: with ISO mdoc, the components follow a namespace (Appendix C.2).
    fn path_for(semantics: ClaimPathSemantics, components: serde_json::Value) -> ClaimPathPointer {
        match semantics {
            ClaimPathSemantics::Mdoc => {
                let mut with_namespace = vec![json!("org.iso.18013.5.1")];
                with_namespace.extend(components.as_array().unwrap().iter().cloned());
                path(serde_json::Value::Array(with_namespace))
            }
            _ => path(components),
        }
    }

    #[test]
    fn claims_descriptions_of_objects_and_arrays_next_to_their_contents_are_valid() {
        for semantics in [
            ClaimPathSemantics::Json,
            ClaimPathSemantics::Mdoc,
            ClaimPathSemantics::Unknown,
        ] {
            let paths = [
                // Section 12.2.4: an object next to a claim in it.
                json!(["address"]),
                json!(["address", "street_address"]),
                // An array next to `null` paths into its items.
                json!(["Courses"]),
                json!(["Courses", null, "Code"]),
                json!(["Courses", null, "Country"]),
                json!(["Websites"]),
                json!(["Websites", null]),
                // Different elements of one array, and different keys of one object.
                json!(["nationalities", 0]),
                json!(["nationalities", 1]),
                json!(["degrees", 0, "type"]),
                json!(["degrees", 0, "university"]),
            ]
            .map(|components| path_for(semantics, components));
            assert_eq!(check(&paths, semantics), Ok(()), "{semantics:?}");
        }
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
            for semantics in [
                ClaimPathSemantics::Json,
                ClaimPathSemantics::Mdoc,
                ClaimPathSemantics::Unknown,
            ] {
                let paths = [path_for(semantics, first.clone()), path_for(semantics, second.clone())];
                let error = check(&paths, semantics).unwrap_err();
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
        for semantics in [
            ClaimPathSemantics::Json,
            ClaimPathSemantics::Mdoc,
            ClaimPathSemantics::Unknown,
        ] {
            let object = path_for(semantics, json!(["address", "street_address"]));
            let array = path_for(semantics, json!(["address", null]));
            assert_eq!(
                check(&[object.clone(), array.clone()], semantics),
                Err(ClaimsDescriptionError::ArrayAndObject { array, object }),
                "{semantics:?}"
            );
        }
        // For JSON-based credentials, an integer is an array index (Appendix C.1). For a format whose data model is
        // not known, B.3 is applied as it reads: an integer implies an array.
        for semantics in [ClaimPathSemantics::Json, ClaimPathSemantics::Unknown] {
            let error = check(
                &[path(json!(["degrees", 0])), path(json!(["degrees", "type"]))],
                semantics,
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
    }

    /// The claims path pointers of Appendix C.3, and one of the W3C VC examples of Appendix A.1.1.2.
    fn json_example_paths() -> Vec<ClaimPathPointer> {
        [
            json!(["name"]),
            json!(["address"]),
            json!(["address", "street_address"]),
            json!(["degrees", null, "type"]),
            json!(["nationalities", 1]),
            json!(["credentialSubject", "given_name"]),
        ]
        .into_iter()
        .map(path)
        .collect()
    }

    /// The ISO mdoc claims path pointers of Appendix A.2.2.
    fn mdoc_example_paths() -> Vec<ClaimPathPointer> {
        [
            json!(["org.iso.18013.5.1", "given_name"]),
            json!(["org.iso.18013.5.1", "family_name"]),
            json!(["org.iso.18013.5.1", "birth_date"]),
            json!(["org.iso.18013.5.1.aamva", "organ_donor"]),
        ]
        .into_iter()
        .map(path)
        .collect()
    }

    /// Paths that start with `null` or a non-negative integer.
    fn paths_into_a_root_array() -> Vec<ClaimPathPointer> {
        [json!([null]), json!([0]), json!([null, "type"]), json!([0, "type"])]
            .into_iter()
            .map(path)
            .collect()
    }

    /// Paths without two leading strings: fewer than two components, or `null` or an integer among the first two.
    fn paths_without_mdoc_namespace_and_data_element() -> Vec<ClaimPathPointer> {
        [
            json!(["org.iso.18013.5.1"]),
            json!(["org.iso.18013.5.1", null]),
            json!(["org.iso.18013.5.1", 0]),
            json!([0, "given_name"]),
            json!([null, "given_name", "x"]),
        ]
        .into_iter()
        .map(path)
        .collect()
    }

    #[test]
    fn a_json_path_starts_with_a_key_of_the_top_level_object() {
        for example in json_example_paths() {
            assert_eq!(example.check_shape(ClaimPathSemantics::Json), Ok(()), "{example:?}");
        }
        for path in paths_into_a_root_array() {
            assert_eq!(
                path.check_shape(ClaimPathSemantics::Json),
                Err(ClaimPathError::JsonRootAsArray { path: path.clone() })
            );
        }
    }

    #[test]
    fn an_mdoc_path_starts_with_a_namespace_and_a_data_element() {
        for example in mdoc_example_paths() {
            assert_eq!(example.check_shape(ClaimPathSemantics::Mdoc), Ok(()), "{example:?}");
        }
        // After the data element, a component can be a map key, an array index or `null`.
        for longer in [
            json!(["org.iso.18013.5.1", "driving_privileges", null, "codes", 0]),
            json!(["org.iso.18013.5.1", "driving_privileges", 1]),
        ] {
            assert_eq!(path(longer).check_shape(ClaimPathSemantics::Mdoc), Ok(()));
        }
        for path in paths_without_mdoc_namespace_and_data_element() {
            assert_eq!(
                path.check_shape(ClaimPathSemantics::Mdoc),
                Err(ClaimPathError::NoMdocNamespaceAndDataElement { path: path.clone() })
            );
        }
    }

    #[test]
    fn with_an_unknown_data_model_no_shape_is_assumed() {
        for path in paths_into_a_root_array()
            .into_iter()
            .chain(paths_without_mdoc_namespace_and_data_element())
        {
            assert_eq!(path.check_shape(ClaimPathSemantics::Unknown), Ok(()), "{path:?}");
        }
    }

    #[test]
    fn the_claims_description_check_refuses_a_path_that_cannot_address_a_claim() {
        let mut json_paths = json_example_paths();
        assert_eq!(check(&json_paths, ClaimPathSemantics::Json), Ok(()));
        json_paths.push(path(json!([null, "type"])));
        let error = check(&json_paths, ClaimPathSemantics::Json).unwrap_err();
        assert_eq!(
            error,
            ClaimsDescriptionError::InvalidPath(ClaimPathError::JsonRootAsArray {
                path: path(json!([null, "type"]))
            })
        );
        assert!(error.to_string().contains("Appendix C.1.1"), "{error}");

        let mut mdoc_paths = mdoc_example_paths();
        assert_eq!(check(&mdoc_paths, ClaimPathSemantics::Mdoc), Ok(()));
        mdoc_paths.push(path(json!(["org.iso.18013.5.1"])));
        let error = check(&mdoc_paths, ClaimPathSemantics::Mdoc).unwrap_err();
        assert_eq!(
            error,
            ClaimsDescriptionError::InvalidPath(ClaimPathError::NoMdocNamespaceAndDataElement {
                path: path(json!(["org.iso.18013.5.1"]))
            })
        );
        assert!(error.to_string().contains("Appendix C.2"), "{error}");
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

    #[test]
    fn many_claims_descriptions_are_checked_without_comparing_every_pair() {
        // Comparing every pair took about 30 seconds in a debug build for 20,000 paths.
        let mut paths: Vec<ClaimPathPointer> = (0..100_000)
            .map(|index| path(json!(["credentialSubject", format!("claim_{index}"), "value"])))
            .collect();
        let started = std::time::Instant::now();
        assert_eq!(check(&paths, ClaimPathSemantics::Json), Ok(()));

        paths.push(path(json!(["credentialSubject", "claim_0", null])));
        assert_eq!(
            check(&paths, ClaimPathSemantics::Json),
            Err(ClaimsDescriptionError::ArrayAndObject {
                array: path(json!(["credentialSubject", "claim_0", null])),
                object: path(json!(["credentialSubject", "claim_0", "value"])),
            })
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_long_path_does_not_overflow_the_stack() {
        // A path is a flat JSON array, so its length is not limited by serde_json's nesting limit.
        let long = path(serde_json::Value::Array(vec![json!("a"); 100_000]));
        let mut longer = long.as_ref().clone();
        longer.push(ClaimPathElement::Null);
        let longer = ClaimPathPointer::try_new(longer).unwrap();
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                assert_eq!(check(std::slice::from_ref(&long), ClaimPathSemantics::Json), Ok(()));
                assert_eq!(check(&[long.clone(), longer.clone()], ClaimPathSemantics::Json), Ok(()));
                assert_eq!(
                    check(&[long.clone(), long.clone()], ClaimPathSemantics::Json),
                    Err(ClaimsDescriptionError::RepeatedClaim { path: long })
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
