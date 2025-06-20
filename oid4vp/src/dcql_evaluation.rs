use oid4vp::claims::{validate_claims, ClaimsContext};
use oid4vp::dcql::dcql_query::{
    ClaimPath, ClaimPathElement, ClaimQuery, ClaimSetQuery, ClaimValue, ClaimValues, CredentialQuery,
    CredentialSetQuery, DcqlQuery,
};
use oid4vp::meta::{validate_meta, MetaContext};
use serde_json::Value;
use validator::{Validate, ValidationErrors};

impl ClaimPath {
    /// As described in OID4VP - draft 28 Section 7.1:
    /// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-processing
    pub fn get_values_from_json(&self, json_data: &Value) -> Vec<Value> {
        /// 1. Select the root element of the Credential, i.e., the top-level JSON object.
        let mut current_selections: Vec<Value> = vec![json_data.clone()];
        for element in self.as_ref().iter() {
            let mut next_selections: Vec<Value> = Vec::new();
            for selected_value in current_selections.drain(..) {
                match element {
                    /// If the component is a string, select the element in the respective key in the currently selected element(s).
                    /// If any of the currently selected element(s) is not an object, abort processing and return an error.
                    /// If the key does not exist in any element currently selected, remove that element from the selection.
                    ClaimPathElement::String(key) => {
                        if let Some(obj) = selected_value.as_object() {
                            if let Some(value_found) = obj.get(key) {
                                next_selections.push(value_found.clone());
                            }
                        }
                    }
                    /// If the component is a non-negative integer, select the element at the respective index in the currently selected array(s).
                    ClaimPathElement::Integer(index) => {
                        if let Some(arr) = selected_value.as_array() {
                            if let Some(value_found) = arr.get(*index as usize) {
                                next_selections.push(value_found.clone());
                            }
                        }
                    }
                    /// If the component is null, select all elements of the currently selected array(s).
                    /// If any of the currently selected element(s) is not an array, abort processing and return an error.
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
            /// If the set of elements currently selected is empty,
            /// abort processing and return an error.
            if current_selections.is_empty() {
                break;
            }
        }
        current_selections
    }
}
