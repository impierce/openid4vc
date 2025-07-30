use crate::utils::predicates::not_empty;
use nutype::nutype;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[nutype(validate(predicate = not_empty), derive(Debug, Clone, PartialEq, Serialize, Deserialize, AsRef))]
pub struct ClaimPathPointer(Vec<ClaimPathElement>);

#[nutype(validate(predicate = not_empty), derive(Debug, Clone, PartialEq, Serialize, AsRef, Deserialize))]
pub struct ClaimValues(Vec<ClaimValue>);

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
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
    /// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-processing
    /// TODO: Add semantics for ISO Mdoc credential format.
    pub fn get_values_from_json(&self, json_data: &Value) -> Vec<Value> {
        let mut current_selections: Vec<Value> = vec![json_data.clone()];
        for element in self.as_ref().iter() {
            let mut next_selections: Vec<Value> = Vec::new();
            for selected_value in current_selections.drain(..) {
                match element {
                    ClaimPathElement::String(key) => {
                        if let Some(obj) = selected_value.as_object() {
                            if let Some(value_found) = obj.get(key) {
                                next_selections.push(value_found.clone());
                            }
                        }
                    }
                    ClaimPathElement::Integer(index) => {
                        if let Some(arr) = selected_value.as_array() {
                            if let Some(value_found) = arr.get(*index as usize) {
                                next_selections.push(value_found.clone());
                            }
                        }
                    }
                    ClaimPathElement::Null => {
                        if let Some(arr) = selected_value.as_array() {
                            for value_in_array in arr {
                                next_selections.push(value_in_array.clone());
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
}

pub fn matches_claim_values(actual_value: &Value, required_value: &ClaimValues) -> bool {
    required_value.as_ref().iter().any(|required_cv| match required_cv {
        ClaimValue::String(s) => actual_value.as_str() == Some(s.as_str()),
        ClaimValue::Integer(i) => actual_value.as_i64() == Some(*i),
        ClaimValue::Boolean(b) => actual_value.as_bool() == Some(*b),
    })
}
