use crate::utils::predicates::not_empty;
use nutype::nutype;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[nutype(validate(predicate = not_empty), derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, AsRef))]
pub struct ClaimPathPointer(Vec<ClaimPathElement>);

#[nutype(validate(predicate = not_empty), derive(Debug, Clone, Eq, PartialEq, Serialize, AsRef, Deserialize))]
pub struct ClaimValues(Vec<ClaimValue>);

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[test]
fn test_index_mut_claim_path_pointer() {
    let mut example: serde_json::Value = serde_json::json!({
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
        ]
    });
    let claim_path_pointer = ClaimPathPointer::try_new(vec![
        ClaimPathElement::String("address".to_string()),
        ClaimPathElement::String("street_address".to_string()),
    ])
    .unwrap();

    let mut values = claim_path_pointer.get_values_from_json_mut(&mut example);
    assert_eq!(values, vec![&mut serde_json::json!("42 Market Street")]);
    *values[0] = serde_json::json!("43 Market Street");

    assert_eq!(
        example,
        serde_json::json!({
            "name": "Arthur Dent",
            "address": {
                "street_address": "43 Market Street",
                "locality": "Milliways",
                "postal_code": "12345"
            },
            "degrees": [
                {
                    "type": "Bachelor of Science",
                    "university": "University of Betelgeuse"
                },
            ]
        })
    );
}

#[derive(Debug, PartialEq)]
pub enum RenameError {
    /// The path did not resolve to a valid location in the JSON data.
    InvalidPath,
    /// The target's parent was not a JSON object, so key renaming is not possible.
    ParentNotAnObject,
    /// The final part of the path was not a string key (e.g., it was an array index).
    TargetPathNotAKey,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum ClaimPathElement {
    /// To address a particular claim within an object, append the key (claim name) to the array.
    String(String),
    /// To address an element within an array, append the index to the array (as a non-negative, 0-based integer).
    Integer(u64),
    /// To address all elements within an array, append a null value to the array.
    Null,
}

impl ClaimPathPointer {
    /// As described in OID4VP - draft 28 Section 7.1 for JSON-based credentials:
    /// https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#name-semantics-for-json-based-cr
    /// TODO: Add semantics for ISO Mdoc credential format.
    pub fn get_values_from_json<'a>(&self, json_data: &'a Value) -> Vec<&'a Value> {
        let mut current_selections: Vec<&Value> = vec![json_data];
        for element in self.as_ref().iter() {
            let mut next_selections: Vec<&Value> = Vec::new();
            for selected_value in current_selections.drain(..) {
                match element {
                    ClaimPathElement::String(key) => {
                        if let Some(obj) = selected_value.as_object() {
                            if let Some(value_found) = obj.get(key) {
                                next_selections.push(value_found);
                            }
                        }
                    }
                    ClaimPathElement::Integer(index) => {
                        if let Some(arr) = selected_value.as_array() {
                            if let Some(value_found) = arr.get(*index as usize) {
                                next_selections.push(value_found);
                            }
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
        current_selections
    }

    pub fn get_values_from_json_mut<'a>(&self, json_data: &'a mut Value) -> Vec<&'a mut Value> {
        let mut current_selections: Vec<&mut Value> = vec![json_data];
        for element in self.as_ref().iter() {
            let mut next_selections: Vec<&mut Value> = Vec::new();
            for selected_value in current_selections.drain(..) {
                match element {
                    ClaimPathElement::String(key) => {
                        if let Some(obj) = selected_value.as_object_mut() {
                            if let Some(value_found) = obj.get_mut(key) {
                                next_selections.push(value_found);
                            }
                        }
                    }
                    ClaimPathElement::Integer(index) => {
                        if let Some(arr) = selected_value.as_array_mut() {
                            if let Some(value_found) = arr.get_mut(*index as usize) {
                                next_selections.push(value_found);
                            }
                        }
                    }
                    ClaimPathElement::Null => {
                        if let Some(arr) = selected_value.as_array_mut() {
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
        current_selections
    }

    /// Renames a key in a JSON object that is pointed to by the `ClaimPathPointer`.
    ///
    /// # Arguments
    ///
    /// * `json_data` - A mutable reference to the `serde_json::Value` to be modified.
    /// * `new_key` - The new name for the key.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The path does not point to a key within a JSON object.
    /// - The path is invalid and does not resolve to any location in the `json_data`.
    pub fn rename_key_in_json(&self, json_data: &mut Value, new_key: String) -> Result<(), RenameError> {
        let path = self.as_ref();
        // The last element is the key to be renamed. The preceding elements are the path to its parent.
        let (key_to_rename, parent_path) = path.split_last().unwrap(); // Safe due to nutype validation.

        // 1. Ensure the target is a string key.
        let old_key = if let ClaimPathElement::String(key) = key_to_rename {
            key
        } else {
            return Err(RenameError::TargetPathNotAKey);
        };

        // 2. Navigate to the parent object(s).
        let mut parents: Vec<&mut Value> = vec![json_data];
        for element in parent_path {
            let mut next_selections: Vec<&mut Value> = Vec::new();
            for selected_value in parents.drain(..) {
                match element {
                    ClaimPathElement::String(key) => {
                        if let Some(value) = selected_value.get_mut(key) {
                            next_selections.push(value);
                        }
                    }
                    ClaimPathElement::Integer(index) => {
                        if let Some(value) = selected_value.get_mut(*index as usize) {
                            next_selections.push(value);
                        }
                    }
                    ClaimPathElement::Null => {
                        if let Some(arr) = selected_value.as_array_mut() {
                            next_selections.extend(arr.iter_mut());
                        }
                    }
                }
            }
            parents = next_selections;
        }

        if parents.is_empty() {
            return Err(RenameError::InvalidPath);
        }

        // 3. For each parent found, perform the rename operation.
        let mut keys_renamed = 0;
        for parent in parents {
            if let Some(obj) = parent.as_object_mut() {
                // Remove the value using the old key, then insert it back with the new key.
                if let Some(value) = obj.remove(old_key) {
                    obj.insert(new_key.clone(), value);
                    keys_renamed += 1;
                }
            } else {
                return Err(RenameError::ParentNotAnObject);
            }
        }

        if keys_renamed == 0 {
            // The parent was found, but the final key did not exist.
            return Err(RenameError::InvalidPath);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Example test case from: https://openid.net/specs/openid-4-verifiable-presentations-1_0-28.html#name-claims-path-pointer-example
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
            .map(|claim_path_pointer| {
                claim_path_pointer
                    .get_values_from_json(&example)
                    .into_iter()
                    .cloned()
                    .collect()
            })
            .collect();

        assert_eq!(selected_values, expected_values);
    }
}
