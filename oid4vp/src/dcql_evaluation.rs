use crate::{
    dcql::dcql_query::{ClaimQuery, CredentialQuery, CredentialSetQuery, DcqlQuery, MetaTypes},
    token::vp_token_validator::{DecodedPresentations, DecodedVpToken},
};
use oid4vc_core::{
    JsonObject,
    claim_path_pointer::{ClaimValue, ClaimValues},
};
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

    // Every Presentation in the VP Token MUST match its Credential Query (OID4VP 1.0, §8.1), also when no required
    // credential set asks for it.
    let presentations_match =
        decoded_vp_token
            .decoded_presentations()
            .iter()
            .all(|(credential_query_id, decoded_presentations)| {
                dcql_query
                    .credentials
                    .iter()
                    .find(|credential_query| credential_query.id == *credential_query_id)
                    .is_some_and(|credential_query| evaluate_credential_query(credential_query, decoded_presentations))
            });
    if !presentations_match {
        tracing::debug!("Presentation does not match its credential query");
        return false;
    }

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
        let present = decoded_vp_token
            .decoded_presentations()
            .contains_key(&credential_query.id);
        if !present {
            tracing::debug!(query_id = %credential_query.id, "Missing presentation for required credential query");
        }
        present
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

/// Whether `decoded_presentations` answer `credential_query`: at most one presentation unless `multiple` is `true`, and
/// each with the type `meta` asks for and the claims of `claims` and `claim_sets` (OID4VP 1.0, §6.1, §6.4.1 and §8.1).
pub fn evaluate_credential_query(
    credential_query: &CredentialQuery,
    decoded_presentations: &DecodedPresentations,
) -> bool {
    // If `multiple` is omitted or `false`, the array MUST contain exactly one Presentation (OID4VP 1.0, §8.1).
    if !credential_query.multiple.unwrap_or_default() && decoded_presentations.len() > 1 {
        return false;
    }

    // Each Presentation in the array MUST match the Credential Query (OID4VP 1.0, §8.1).
    decoded_presentations.iter().all(|decoded_presentation| {
        // TODO: Check `require_cryptographic_holder_binding`
        matches_meta(&credential_query.meta, decoded_presentation)
            && matches_claims(credential_query, decoded_presentation)
    })
}

/// Whether `decoded_presentation` has the type `meta` asks for.
fn matches_meta(meta: &MetaTypes, decoded_presentation: &JsonObject) -> bool {
    match meta {
        MetaTypes::W3CFormatMeta { type_values } => {
            // For W3C Verifiable Credentials, check the "type" field in the credential
            let Some(credential_types) = decoded_presentation.get("type").and_then(|t| t.as_array()) else {
                return false;
            };
            let credential_type_strings: Vec<&str> = credential_types.iter().filter_map(|t| t.as_str()).collect();

            // Check if any of the type_values arrays is a subset of the credential's types
            type_values.iter().any(|type_option| {
                type_option
                    .iter()
                    .all(|required_type| credential_type_strings.contains(&required_type.as_str()))
            })
        }
        MetaTypes::SdJwtMeta { vct_values } => decoded_presentation
            .get("vct")
            .and_then(|v| v.as_str())
            .is_some_and(|vct_string| vct_values.iter().any(|required_vct| required_vct == vct_string)),
        MetaTypes::MsoMdocMeta {
            doctype_value: _doctype_value,
        } => {
            // TODO: Implement MSO mDoc type checking
            true
        }
    }
}

/// Whether `decoded_presentation` has the claims `claims` and `claim_sets` ask for.
fn matches_claims(credential_query: &CredentialQuery, decoded_presentation: &JsonObject) -> bool {
    // If claims is absent, the Verifier is requesting no claims that are selectively disclosable;
    // the Wallet MUST return only the claims that are mandatory to present (e.g., SD-JWT and Key Binding JWT for a Credential of format IETF SD-JWT VC).
    let claims = credential_query.claims.as_deref().unwrap_or(&[]);
    if claims.is_empty() {
        return true;
    }

    let presentation_value = serde_json::Value::Object(decoded_presentation.clone());

    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims.
    match &credential_query.claim_sets {
        None => claims
            .iter()
            .all(|claim| evaluate_single_claim_query(claim, &presentation_value)),

        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets. The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet SHOULD return the first option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT return any claims.
        Some(claim_sets) => claim_sets.iter().any(|claim_set| {
            claim_set.iter().all(|claim_id| {
                claims
                    .iter()
                    .find(|claim| claim.id.as_ref() == Some(claim_id))
                    .is_some_and(|claim| evaluate_single_claim_query(claim, &presentation_value))
            })
        }),
    }
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
        dcql::claims::{ClaimsContext, validate_claims},
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
        validate_claims(dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

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
        validate_claims(dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

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
        validate_claims(dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

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
        validate_claims(dcql_query.claims.as_deref().unwrap_or(&[]), &claims_context).unwrap();

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

    /// A `dc+sd-jwt` Credential Query for `identity_credential`, with `multiple` and `claims` as given.
    fn identity_credential_query(multiple: Option<bool>, claims: Option<Value>) -> CredentialQuery {
        let mut query = json!({
            "id": "identity",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["https://credentials.example.com/identity_credential"] },
        });
        if let Some(multiple) = multiple {
            query["multiple"] = json!(multiple);
        }
        if let Some(claims) = claims {
            query["claims"] = claims;
        }
        serde_json::from_value(query).unwrap()
    }

    fn presentations(credentials: &[Value]) -> DecodedPresentations {
        DecodedPresentations::try_new(
            credentials
                .iter()
                .map(|credential| credential.as_object().unwrap().clone())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn every_presentation_must_match_a_query_with_multiple() {
        let query = identity_credential_query(Some(true), Some(json!([{ "path": ["email"] }])));
        let matching = json!({
            "vct": "https://credentials.example.com/identity_credential",
            "email": "ferris.crabman@crabmail.com",
        });
        let without_email = json!({ "vct": "https://credentials.example.com/identity_credential" });
        let other_type = json!({
            "vct": "https://credentials.example.com/residence_credential",
            "email": "ferris.crabman@crabmail.com",
        });

        assert!(evaluate_credential_query(
            &query,
            &presentations(&[matching.clone(), matching.clone()])
        ));
        assert!(!evaluate_credential_query(
            &query,
            &presentations(&[matching.clone(), without_email])
        ));
        assert!(!evaluate_credential_query(
            &query,
            &presentations(&[other_type, matching])
        ));
    }

    #[test]
    fn more_than_one_presentation_fails_a_query_without_multiple() {
        let credential = json!({ "vct": "https://credentials.example.com/identity_credential" });

        for multiple in [None, Some(false)] {
            assert!(!evaluate_credential_query(
                &identity_credential_query(multiple, None),
                &presentations(&[credential.clone(), credential.clone()])
            ));
        }
    }

    #[test]
    fn meta_is_checked_without_claims() {
        let query = identity_credential_query(None, None);

        assert!(evaluate_credential_query(
            &query,
            &presentations(&[json!({ "vct": "https://credentials.example.com/identity_credential" })])
        ));
        assert!(!evaluate_credential_query(
            &query,
            &presentations(&[json!({ "vct": "https://credentials.example.com/residence_credential" })])
        ));
        assert!(!evaluate_credential_query(&query, &presentations(&[json!({})])));
    }

    #[test]
    fn presentation_for_an_optional_credential_set_must_match() {
        let dcql_query: DcqlQuery = serde_json::from_str(TESTCREDENTIALQUERY_WITH_SETS).unwrap();
        let pid = json!({
            "vct": "https://credentials.example.com/identity_credential",
            "given_name": "John",
            "family_name": "Doe",
            "address": { "street_address": "123 Main St" }
        });
        let decoded_vp_token = |nice_to_have: Value| {
            DecodedVpTokenBuilder::new()
                .insert("pid".parse().unwrap(), vec![pid.as_object().unwrap().clone()])
                .unwrap()
                .insert(
                    "nice_to_have".parse().unwrap(),
                    vec![nice_to_have.as_object().unwrap().clone()],
                )
                .unwrap()
                .build()
        };

        assert!(evaluate_dcql_query(
            &dcql_query,
            &decoded_vp_token(json!({
                "vct": "https://company.example/company_rewards",
                "rewards_number": "12345"
            }))
        ));
        // `nice_to_have` is in an optional set only, and this presentation has another type.
        assert!(!evaluate_dcql_query(
            &dcql_query,
            &decoded_vp_token(json!({
                "vct": "https://credentials.example.com/identity_credential",
                "rewards_number": "12345"
            }))
        ));
    }

    #[test]
    fn presentation_for_another_option_of_a_required_set_must_match() {
        let dcql_query: DcqlQuery = serde_json::from_str(TESTCREDENTIALQUERY_WITH_SETS).unwrap();
        let pid = json!({
            "vct": "https://credentials.example.com/identity_credential",
            "given_name": "John",
            "family_name": "Doe",
            "address": { "street_address": "123 Main St" }
        });
        // `other_pid` without the claims its query asks for, next to a `pid` that satisfies the set.
        let other_pid = json!({ "vct": "https://othercredentials.example/pid" });
        let decoded_vp_token = DecodedVpTokenBuilder::new()
            .insert("pid".parse().unwrap(), vec![pid.as_object().unwrap().clone()])
            .unwrap()
            .insert(
                "other_pid".parse().unwrap(),
                vec![other_pid.as_object().unwrap().clone()],
            )
            .unwrap()
            .build();

        assert!(!evaluate_dcql_query(&dcql_query, &decoded_vp_token));
    }
}
