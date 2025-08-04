use crate::dcql::dcql_query::{ClaimQuery, CredentialQuery};
use oid4vc_core::claim_path_pointer::matches_claim_values;
use serde_json::Value;

fn evaluate_single_claim_query(claim_query: &ClaimQuery, credential_json: &Value) -> bool {
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
    // If claims is absent, the Verifier is requesting no claims that are selectively disclosable;
    // the Wallet MUST return only the claims that are mandatory to present (e.g., SD-JWT and Key Binding JWT for a Credential of format IETF SD-JWT VC).
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
    use crate::dcql::claims::{validate_claims, ClaimsContext};
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer, ClaimValue, ClaimValues};
    use serde_json::json;

    const TESTCREDENTIAL: &str = include_str!("../tests/examples/credentials/jwt_vc.json");
    const DCQL_QUERY: &str = include_str!("../tests/examples/request/dcql_jwt_vc.json");
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

    #[test]
    fn test_evaluate_single_claim_query() {
        let testing_credential: Value = serde_json::from_str(TESTCREDENTIAL).unwrap();
        let claim_query = ClaimQuery {
            id: Some("given_name".to_string()),
            path: ClaimPathPointer::try_new(vec![
                ClaimPathElement::String("vc".to_string()),
                ClaimPathElement::String("credentialSubject".to_string()),
                ClaimPathElement::String("given_name".to_string()),
            ])
            .unwrap(),
            values: Some(ClaimValues::try_new(vec![ClaimValue::String("Max".to_string())]).unwrap()),
        };
        // Returns true
        assert!(evaluate_single_claim_query(&claim_query, &testing_credential));
    }

    #[test]
    fn evaluate_single_invalid_claim_query() {
        let testing_credential = json!({
                "vc": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "IDCredential"
            ],
            "credentialSubject": {
                "given_name": "Rainer",
                "family_name": "Zufall",
                "birthdate": "1998-01-11",
                "address": {
                    "street_address": "Sandanger 25",
                    "locality": "Musterstadt",
                    "postal_code": "123456",
                    "country": "DE"
                }
            }
        }
            });
        let claim_query = ClaimQuery {
            id: Some("given_name".to_string()),
            path: ClaimPathPointer::try_new(vec![
                ClaimPathElement::String("vc".to_string()),
                ClaimPathElement::String("credentialSubject".to_string()),
                ClaimPathElement::String("given_name".to_string()),
            ])
            .unwrap(),
            values: Some(ClaimValues::try_new(vec![ClaimValue::String("Max".to_string())]).unwrap()),
        };
        // Returns false
        assert!(!evaluate_single_claim_query(&claim_query, &testing_credential));
    }

    #[derive(Debug, serde::Deserialize)]
    pub struct DcqlRequest {
        pub credentials: Vec<CredentialQuery>,
    }

    #[test]
    fn test_dcql_credential_query() {
        let testing_credential = json!({
            "iss": "https://example.gov/issuers/565049",
            "nbf": 1262304000,
            "jti": "http://example.gov/credentials/3732",
            "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "type": [
                "VerifiableCredential",
                "IDCredential"
            ],
            "credentialSubject": {
                "given_name": "Rainer",
                "family_name": "Zufall",
                "birthdate": "1998-01-11",
                "address": {
                    "street_address": "Sandanger 25",
                    "locality": "Musterstadt",
                    "postal_code": "123456",
                    "country": "DE"
                }
            }
        });
        let dcql_request: DcqlRequest = serde_json::from_str(DCQL_QUERY).unwrap();
        let dcql_query = &dcql_request.credentials[0];

        let claims_context = ClaimsContext {
            claim_sets: &dcql_query.claim_sets,
        };
        validate_claims(&dcql_query.claims, &claims_context).unwrap();

        assert!(evaluate_credential_query(dcql_query, &testing_credential));
    }
}
