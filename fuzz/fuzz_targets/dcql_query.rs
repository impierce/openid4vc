//! DCQL (OID4VP, "Digital Credentials Query Language"): a query parses from JSON or not, validates
//! or not, serializes to JSON that deserializes to the same query, and evaluates against any set of
//! decoded presentations without panicking. Claim Path Pointers select from any JSON document.
//!
//! The input is JSON: a DCQL query; or an object with `dcql_query` and `presentations` (Credential
//! Query identifier to an array of decoded credentials); or an object with `path` and `value`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oid4vc_core::claim_path_pointer::ClaimPathPointer;
use oid4vp::dcql::dcql_query::{CredentialQueryId, DcqlQuery};
use oid4vp::dcql_evaluation::{evaluate_dcql_query, matches_claim_values};
use oid4vp::token::vp_token_validator::DecodedVpTokenBuilder;
use serde_json::{Map, Value};

fn exercise(query: &DcqlQuery) {
    let _ = query.validate_all();
    let json = serde_json::to_value(query).expect("a DCQL query serializes");
    let again: DcqlQuery = serde_json::from_value(json).expect("a serialized DCQL query parses");
    assert_eq!(&again, query);
}

fn evaluate(query: &DcqlQuery, presentations: &Map<String, Value>) {
    let mut builder = DecodedVpTokenBuilder::new();
    for (id, credentials) in presentations {
        let Ok(id) = CredentialQueryId::try_new(id.as_str()) else {
            continue;
        };
        let credentials: Vec<_> = credentials
            .as_array()
            .map(|credentials| credentials.iter().filter_map(Value::as_object).cloned().collect())
            .unwrap_or_default();
        if credentials.is_empty() {
            continue;
        }
        builder = builder.insert(id, credentials).expect("non-empty presentations insert");
    }
    let token = builder.build();
    let _ = evaluate_dcql_query(query, &token);

    for credential_query in &query.credentials {
        for claim in credential_query.claims.iter().flatten() {
            for presentations in token.decoded_presentations().values() {
                for credential in presentations.iter() {
                    let found = claim.path.get_values_from_json(&Value::Object(credential.clone()));
                    if let Some(values) = &claim.values {
                        for value in &found {
                            let _ = matches_claim_values(value, values);
                        }
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    if let Ok(query) = serde_json::from_value::<DcqlQuery>(value.clone()) {
        exercise(&query);
    }
    let Some(object) = value.as_object() else {
        return;
    };

    if let (Some(query), Some(presentations)) = (
        object.get("dcql_query"),
        object.get("presentations").and_then(Value::as_object),
    ) {
        if let Ok(query) = serde_json::from_value::<DcqlQuery>(query.clone()) {
            exercise(&query);
            evaluate(&query, presentations);
        }
    }

    if let (Some(path), Some(root)) = (object.get("path"), object.get("value")) {
        if let Ok(path) = serde_json::from_value::<ClaimPathPointer>(path.clone()) {
            let json = serde_json::to_value(&path).expect("a claim path pointer serializes");
            let again: ClaimPathPointer = serde_json::from_value(json).expect("a serialized claim path pointer parses");
            assert_eq!(again, path);
            let _ = path.get_values_from_json(root);
        }
    }
});
