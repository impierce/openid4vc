use crate::{
    dcql::dcql_query::{ClaimQuery, CredentialQuery, CredentialSetQuery, DcqlQuery, MetaTypes},
    token::vp_token_validator::{DecodedPresentations, DecodedVpToken},
};
use oid4vc_core::claim_path_pointer::{ClaimValue, ClaimValues};
use serde_json::Value;

/// Processing a dcql_query with credential sets as described in OID4VP - Section 6.4.2 Selecting Credentials:
/// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-credentials
fn set_is_required(credential_set: &CredentialSetQuery) -> bool {
    credential_set.required.unwrap_or(true)
}

pub fn evaluate_dcql_query(dcql_query: &DcqlQuery, decoded_vp_token: &DecodedVpToken) -> bool {
    tracing::debug!(
        credentials_count = dcql_query.credentials.len(),
        has_sets = dcql_query.credential_sets.is_some(),
        "Evaluating DCQL query against decoded VP token"
    );

    // If there are credential sets, check if all required sets can be satisfied.
    if let Some(credential_sets) = &dcql_query.credential_sets {
        // All of the Credential Set Queries in the credential_sets array where
        // the required attribute is true or omitted must be satisfied
        let required_sets_satisfied = credential_sets.iter().all(|credential_set| {
            let is_required_set = set_is_required(credential_set);
            if !is_required_set {
                return true;
            }

            // Check if the required set has at least one satisfiable option.
            evaluate_credential_set(credential_set, &dcql_query.credentials, decoded_vp_token)
        });

        tracing::debug!(required_sets_satisfied, "DCQL credential sets evaluation result");
        return required_sets_satisfied;
    }

    // If credential_sets is not provided, the Verifier requests presentations for all Credentials in credentials to be returned.
    let result = dcql_query.credentials.iter().all(|credential_query| {
        if let Some(decoded_presentations) = decoded_vp_token.decoded_presentations().get(&credential_query.id) {
            evaluate_credential_query(credential_query, decoded_presentations)
        } else {
            tracing::debug!(query_id = %credential_query.id, "Missing presentation for required credential query");
            false
        }
    });
    tracing::debug!(result, "DCQL query evaluation result");
    result
}

// To satisfy a Credential Set Query, the Wallet MUST return presentations of a set of Credentials that
// match to one of the options inside the Credential Set Query.
pub fn evaluate_credential_set(
    credential_set: &CredentialSetQuery,
    all_credentials: &[CredentialQuery],
    available_credentials: &DecodedVpToken,
) -> bool {
    credential_set.options.iter().any(|option| {
        option.iter().all(|credential_query_id| {
            if let Some(credential_query) = all_credentials.iter().find(|cq| cq.id == *credential_query_id) {
                if let Some(credential_json) = available_credentials.decoded_presentations().get(credential_query_id) {
                    evaluate_credential_query(credential_query, credential_json)
                } else {
                    false
                }
            } else {
                false
            }
        })
    })
}

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

/// Processing with claims_sets as described in OID4VP Section 6.4.1 Selecting Claims:
/// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-claims
pub fn evaluate_credential_query(
    credential_query: &CredentialQuery,
    decoded_presentations: &DecodedPresentations,
) -> bool {
    // If claims is absent, the Verifier is requesting no claims that are selectively disclosable;
    // the Wallet MUST return only the claims that are mandatory to present (e.g., SD-JWT and Key Binding JWT for a Credential of format IETF SD-JWT VC).
    if credential_query.claims.as_deref().unwrap_or(&[]).is_empty() {
        return true;
    }

    // If `multiple` is `false`, the Verifier is requesting that only one presentation of a Credential matching the Credential Query be returned.
    if !credential_query.multiple.unwrap_or_default() && decoded_presentations.len() > 1 {
        return false;
    }

    decoded_presentations.iter().any(|decoded_presentation| {
        // If meta is present, check the meta requirements.
        match &credential_query.meta {
            MetaTypes::W3CFormatMeta { type_values } => {
                // For W3C Verifiable Credentials, check the "type" field in the credential
                if let Some(credential_types) = decoded_presentation.get("type").and_then(|t| t.as_array()) {
                    let credential_type_strings: Vec<&str> =
                        credential_types.iter().filter_map(|t| t.as_str()).collect();

                    // Check if any of the type_values arrays is a subset of the credential's types
                    let type_match = type_values.iter().any(|type_option| {
                        type_option
                            .iter()
                            .all(|required_type| credential_type_strings.contains(&required_type.as_str()))
                    });

                    if !type_match {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            MetaTypes::SdJwtMeta { vct_values } => {
                if let Some(vct_string) = decoded_presentation.get("vct").and_then(|v| v.as_str()) {
                    let type_match = vct_values.iter().any(|required_vct| required_vct == vct_string);

                    if !type_match {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            MetaTypes::MsoMdocMeta {
                doctype_value: _doctype_value,
            } => {
                // TODO: Implement MSO mDoc type checking
            }
        }

        // TODO: Check `trusted_authorities` if present
        // TODO: Check `require_cryptographic_holder_binding`

        let presentation_value = serde_json::Value::Object(decoded_presentation.clone());

        // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims.
        match &credential_query.claim_sets {
            None => credential_query
                .claims
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .all(|claim| evaluate_single_claim_query(claim, &presentation_value)),

            // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets. The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
            // the Wallet SHOULD return the first option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT return any claims.
            Some(claim_sets) => claim_sets.iter().any(|claim_set| {
                claim_set.iter().all(|claim_id| {
                    credential_query
                        .claims
                        .as_ref()
                        .and_then(|claims| claims.iter().find(|claim| claim.id.as_ref() == Some(claim_id)))
                        .is_some_and(|claim| evaluate_single_claim_query(claim, &presentation_value))
                })
            }),
        }
    })
}

pub fn matches_claim_values(actual_value: &Value, required_value: &ClaimValues) -> bool {
    required_value.as_ref().iter().any(|required_cv| match required_cv {
        ClaimValue::String(s) => actual_value.as_str() == Some(s.as_str()),
        ClaimValue::Integer(i) => actual_value.as_i64() == Some(*i),
        ClaimValue::Boolean(b) => actual_value.as_bool() == Some(*b),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dcql::claims::{validate_claims, ClaimsContext},
        token::vp_token_validator::DecodedVpTokenBuilder,
    };
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer, ClaimValue, ClaimValues};
    use serde_json::json;

    const TESTCREDENTIAL: &str = include_str!("../tests/examples/credentials/jwt_vc.json");
    const DCQL_QUERY: &str = include_str!("../tests/examples/request/dcql_jwt_vc.json");
    const TESTCREDENTIALQUERY_WITH_SETS: &str =
        include_str!("../tests/examples/query_lang/credentials_alternatives.json");

    #[test]
    fn test_get_value_from_json() {
        let testing_credential: Value = serde_json::from_str(TESTCREDENTIAL).unwrap();
        let path = ClaimPathPointer::try_new(vec![
            ClaimPathElement::String("credentialSubject".to_string()),
            ClaimPathElement::String("given_name".to_string()),
        ])
        .unwrap();
        let values = path.get_values_from_json(&testing_credential["vc"]);
        assert_eq!(values, vec![json!("Max")]);
    }

    #[test]
    fn test_evaluate_single_claim_query() {
        let testing_credential: Value = serde_json::from_str(TESTCREDENTIAL).unwrap();
        let claim_query = ClaimQuery {
            id: Some("given_name".to_string()),
            path: ClaimPathPointer::try_new(vec![
                ClaimPathElement::String("credentialSubject".to_string()),
                ClaimPathElement::String("given_name".to_string()),
            ])
            .unwrap(),
            values: Some(ClaimValues::try_new(vec![ClaimValue::String("Max".to_string())]).unwrap()),
        };
        // Returns true
        assert!(evaluate_single_claim_query(&claim_query, &testing_credential["vc"]));
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
        let dcql_request: DcqlRequest = serde_json::from_str(DCQL_QUERY).unwrap();
        let dcql_query = &dcql_request.credentials[0];

        let claims_context = ClaimsContext {
            claim_sets: &dcql_query.claim_sets,
        };
        validate_claims(&dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

        assert!(evaluate_credential_query(
            dcql_query,
            &DecodedPresentations::try_new(vec![testing_credential.get("vc").unwrap().as_object().unwrap().clone()])
                .unwrap()
        ));
    }

    #[test]
    fn test_dcql_credential_query_with_incompatible_type_values() {
        let testing_credential = json!({
            "iss": "http://192.168.1.127:9090/",
            "sub": "did:key:z6Mkg1XXGUqfkhAKU1kVd1Pmw6UEj1vxiLj1xc91MBz5owNY",
            "exp": 99999999,
            "iat": 0,
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "PersonalInformation"
                ],
                "issuanceDate": "2022-01-01T00:00:00Z",
                "issuer": "http://192.168.1.127:9090/",
                "credentialSubject": {
                    "id": "did:key:z6Mkg1XXGUqfkhAKU1kVd1Pmw6UEj1vxiLj1xc91MBz5owNY",
                    "givenName": "Ferris",
                    "familyName": "Crabman",
                    "email": "ferris.crabman@crabmail.com",
                    "birthdate": "1985-05-21"
                }
            }
        });
        let dcql_request: DcqlRequest = serde_json::from_value(serde_json::json!({
            "credentials": [
                {
                    "id": "login",
                    "format": "jwt_vc_json",
                    "meta": {
                        "type_values": [["VerifiedEmail"]]
                    },
                    "claims": [{ "path": ["credentialSubject", "email"] }]
                }
            ]
        }))
        .unwrap();
        let dcql_query = &dcql_request.credentials[0];

        let claims_context = ClaimsContext {
            claim_sets: &dcql_query.claim_sets,
        };
        validate_claims(&dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

        // Assert `false` because the credential type does not match the required type in the query.
        assert!(!evaluate_credential_query(
            dcql_query,
            &DecodedPresentations::try_new(vec![testing_credential.get("vc").unwrap().as_object().unwrap().clone()])
                .unwrap()
        ));
    }

    #[test]
    fn test_dcql_credential_query_with_compatible_vct_values() {
        let testing_credential = json!({
            "vct": "https://credentials.example.com/identity_credential",
            "given_name": "Ferris",
            "family_name": "Crabman",
            "email": "ferris.crabman@crabmail.com",
            "birthdate": "1985-05-21"
        });
        let dcql_request: DcqlRequest = serde_json::from_value(serde_json::json!({
            "credentials": [
                {
                    "id": "login",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                    },
                    "claims": [{ "path": ["email"] }]
                }
            ]
        }))
        .unwrap();
        let dcql_query = &dcql_request.credentials[0];

        let claims_context = ClaimsContext {
            claim_sets: &dcql_query.claim_sets,
        };
        validate_claims(&dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

        assert!(evaluate_credential_query(
            dcql_query,
            &DecodedPresentations::try_new(vec![testing_credential.as_object().unwrap().clone()]).unwrap()
        ));
    }

    #[test]
    fn test_dcql_credential_query_with_incompatible_vct_values() {
        let testing_credential = json!({
            "vct": "https://credentials.example.com/identity_credential",
            "given_name": "Ferris",
            "family_name": "Crabman",
            "email": "ferris.crabman@crabmail.com",
            "birthdate": "1985-05-21"
        });
        let dcql_request: DcqlRequest = serde_json::from_value(serde_json::json!({
            "credentials": [
                {
                    "id": "login",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://credentials.example.com/verified_email"]
                    },
                    "claims": [{ "path": ["email"] }]
                }
            ]
        }))
        .unwrap();
        let dcql_query = &dcql_request.credentials[0];

        let claims_context = ClaimsContext {
            claim_sets: &dcql_query.claim_sets,
        };
        validate_claims(&dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

        // Assert `false` because the credential vct does not match the required vct_values in the query.
        assert!(!evaluate_credential_query(
            dcql_query,
            &DecodedPresentations::try_new(vec![testing_credential.as_object().unwrap().clone()]).unwrap()
        ));
    }

    #[test]
    fn test_dcql_query_with_credential_sets() {
        let dcql_query: DcqlQuery = serde_json::from_str(TESTCREDENTIALQUERY_WITH_SETS).unwrap();

        // Simplified version of a credential that satisfies the first option (pid)
        let pid_credential = json!({
            "vct": "https://credentials.example.com/identity_credential",
            "given_name": "John",
            "family_name": "Doe",
            "address": {
                "street_address": "123 Main St"
            }
        });

        let mut builder = DecodedVpTokenBuilder::new();

        builder = builder
            .insert(
                "pid".parse().unwrap(),
                vec![pid_credential.as_object().unwrap().clone()],
            )
            .unwrap();

        assert!(evaluate_dcql_query(&dcql_query, &builder.build()));

        // Alternative credentials (pid_reduced_cred_1 + pid_reduced_cred_2)
        let reduced_cred_1 = json!({
            "vct":"https://credentials.example.com/reduced_identity_credential",
            "given_name": "John",
            "family_name": "Doe"
        });

        let reduced_cred_2 = json!({
            "vct":"https://cred.example/residence_credential",
            "postal_code": "12345",
            "locality": "Somewhere",
            "region": "HERE"
        });

        let mut builder = DecodedVpTokenBuilder::new();
        builder = builder
            .insert(
                "pid_reduced_cred_1".parse().unwrap(),
                vec![reduced_cred_1.as_object().unwrap().clone()],
            )
            .unwrap();
        builder = builder
            .insert(
                "pid_reduced_cred_2".parse().unwrap(),
                vec![reduced_cred_2.as_object().unwrap().clone()],
            )
            .unwrap();

        assert!(evaluate_dcql_query(&dcql_query, &builder.build()));

        // If there were no credentials, the query should fail.
        let builder = DecodedVpTokenBuilder::new();

        assert!(!evaluate_dcql_query(&dcql_query, &builder.build()));
    }
}
