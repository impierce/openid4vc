use crate::dcql::dcql_query::{ClaimQuery, CredentialQuery};
use oid4vc_core::claim_path_pointer::matches_claim_values;
use serde_json::Value;

pub fn evaluate_single_claim_query(claim_query: &ClaimQuery, credential_json: &Value) -> bool {
    let extracted_values = claim_query.path.get_values_from_json(credential_json);
    if extracted_values.is_empty() {
        return false;
    }
    if let Some(required_claim_values) = &claim_query.values {
        let any_extracted_value_match = extracted_values
            .iter()
            .any(|extracted_val| matches_claim_values(extracted_val, required_claim_values));

        if !any_extracted_value_match {
            return false;
        }
    }
    true
}

/// Processing with claims_sets as described in OID4VP - draft 28 Section 6.4.1 Selecting Claims:
/// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims-and-credentials
pub fn evaluate_credential_query(credential_query: &CredentialQuery, credential_json: &Value) -> bool {
    //If claims is absent, the Verifier is requesting no claims that are selectively disclosable;
    //the Wallet MUST return only the claims that are mandatory to present (e.g., SD-JWT and Key Binding JWT for a Credential of format IETF SD-JWT VC).
    if credential_query.claims.is_empty() {
        return true;
    }
    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims.
    match &credential_query.claim_sets {
        None => credential_query
            .claims
            .iter()
            .all(|claim| evaluate_single_claim_query(claim, credential_json)),

        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets. The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet SHOULD return the first option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT return any claims.
        Some(claim_sets) => claim_sets.iter().any(|claim_set| {
            claim_set.iter().all(|claim_id| {
                credential_query
                    .claims
                    .iter()
                    .find(|claim| claim.id.as_ref() == Some(claim_id))
                    .is_some_and(|claim| evaluate_single_claim_query(claim, credential_json))
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer};
    use serde_json::json;

    const TESTCREDENTIAL: &str = include_str!("../tests/examples/credentials/jwt_vc.json");

    #[test]
    fn test_get_value_from_json() {
        let testing_credential: Value = serde_json::from_str(TESTCREDENTIAL).unwrap();
        let path = ClaimPathPointer::try_new(vec![
            ClaimPathElement::String("vc".to_string()),
            ClaimPathElement::String("credentialSubject".to_string()),
            ClaimPathElement::String("given_name".to_string()),
        ])
        .unwrap();
        let values = path.get_values_from_json(&testing_credential);
        assert_eq!(values, vec![json!("Max")]);
    }
}
