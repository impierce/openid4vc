use crate::{
    dcql::dcql_query::{ClaimQuery, CredentialQuery, CredentialQueryId, CredentialSetQuery, DcqlQuery, MetaTypes},
    token::vp_token_validator::{DecodedPresentations, DecodedVpToken},
};
use oid4vc_core::{
    JsonObject,
    claim_path_pointer::{ClaimPathProcessingError, ClaimValue, ClaimValues},
};
use serde_json::Value;

/// Why a DCQL query could not be evaluated against a VP token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DcqlEvaluationError {
    /// The path of a claims query does not fit a presentation for its credential query: a key on an element that
    /// is not an object, or `null` or an index on an element that is not an array (OID4VP 1.0, Section 7.1.1). A
    /// claim that is not in the presentation is no error: the claims query is not satisfied.
    #[error("A claims query of credential query `{credential_query_id}` does not fit its presentation: {source}")]
    ClaimPath {
        credential_query_id: CredentialQueryId,
        #[source]
        source: ClaimPathProcessingError,
    },
}

/// Processing a dcql_query with credential sets as described in OID4VP - Section 6.4.2 Selecting Credentials:
/// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-selecting-credentials
fn set_is_required(credential_set: &CredentialSetQuery) -> bool {
    credential_set.required.unwrap_or(true)
}

/// Whether `decoded_vp_token` answers `dcql_query` (OID4VP 1.0, Section 6.4.2 and 8.1).
///
/// Every presentation is evaluated against its credential query, so whether there is an error does not depend on
/// the order of evaluation: there is one if any claims query does not fit a presentation for its credential query
/// ([`DcqlEvaluationError::ClaimPath`]).
pub fn evaluate_dcql_query(
    dcql_query: &DcqlQuery,
    decoded_vp_token: &DecodedVpToken,
) -> Result<bool, DcqlEvaluationError> {
    tracing::debug!(
        credentials_count = dcql_query.credentials.len(),
        has_sets = dcql_query.credential_sets.is_some(),
        "Evaluating DCQL query against decoded VP token"
    );

    // Every Presentation in the VP Token MUST match its Credential Query (OID4VP 1.0, §8.1), also when no required
    // credential set asks for it.
    let mut presentations_match = true;
    for (credential_query_id, decoded_presentations) in decoded_vp_token.decoded_presentations() {
        let matches = match dcql_query
            .credentials
            .iter()
            .find(|credential_query| credential_query.id == *credential_query_id)
        {
            Some(credential_query) => evaluate_credential_query(credential_query, decoded_presentations)?,
            None => false,
        };
        presentations_match &= matches;
    }
    if !presentations_match {
        tracing::debug!("Presentation does not match its credential query");
        return Ok(false);
    }

    // If there are credential sets, check if all required sets can be satisfied.
    if let Some(credential_sets) = &dcql_query.credential_sets {
        // All of the Credential Set Queries in the credential_sets array where
        // the required attribute is true or omitted must be satisfied
        let mut required_sets_satisfied = true;
        for credential_set in credential_sets {
            // Check if the required set has at least one satisfiable option.
            if set_is_required(credential_set) {
                required_sets_satisfied &=
                    evaluate_credential_set(credential_set, &dcql_query.credentials, decoded_vp_token)?;
            }
        }

        tracing::debug!(required_sets_satisfied, "DCQL credential sets evaluation result");
        return Ok(required_sets_satisfied);
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
    Ok(result)
}

// To satisfy a Credential Set Query, the Wallet MUST return presentations of a set of Credentials that
// match to one of the options inside the Credential Set Query.
//
// Every credential query of every option that has presentations is evaluated, so whether there is an error does
// not depend on the order of the options.
pub fn evaluate_credential_set(
    credential_set: &CredentialSetQuery,
    all_credentials: &[CredentialQuery],
    available_credentials: &DecodedVpToken,
) -> Result<bool, DcqlEvaluationError> {
    let mut any_option_satisfied = false;
    for option in &credential_set.options {
        let mut option_satisfied = true;
        for credential_query_id in option {
            let credential_query = all_credentials.iter().find(|cq| cq.id == *credential_query_id);
            let presentations = available_credentials.decoded_presentations().get(credential_query_id);
            option_satisfied &= match (credential_query, presentations) {
                (Some(credential_query), Some(presentations)) => {
                    evaluate_credential_query(credential_query, presentations)?
                }
                _ => false,
            };
        }
        any_option_satisfied |= option_satisfied;
    }
    Ok(any_option_satisfied)
}

/// Whether `credential_json` has the claim `claim_query` asks for, with one of its `values` if it has any. A claim
/// that is not in the credential does not satisfy the claims query; a path that does not fit the credential is an
/// error (OID4VP 1.0, Section 7.1.1).
fn evaluate_single_claim_query(
    claim_query: &ClaimQuery,
    credential_json: &Value,
) -> Result<bool, ClaimPathProcessingError> {
    let extracted_values = match claim_query.path.get_values_from_json(credential_json) {
        Ok(extracted_values) => extracted_values,
        Err(ClaimPathProcessingError::NothingSelected { .. }) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(match &claim_query.values {
        Some(required_claim_values) => extracted_values
            .iter()
            .any(|extracted_val| matches_claim_values(extracted_val, required_claim_values)),
        None => true,
    })
}

/// Whether `decoded_presentations` answer `credential_query`: at most one presentation unless `multiple` is `true`, and
/// each with the type `meta` asks for and the claims of `claims` and `claim_sets` (OID4VP 1.0, §6.1, §6.4.1 and §8.1).
///
/// The claims queries are evaluated against every presentation, so whether there is an error does not depend on
/// the order of the presentations or of the claims queries.
pub fn evaluate_credential_query(
    credential_query: &CredentialQuery,
    decoded_presentations: &DecodedPresentations,
) -> Result<bool, DcqlEvaluationError> {
    // If `multiple` is omitted or `false`, the array MUST contain exactly one Presentation (OID4VP 1.0, §8.1).
    if !credential_query.multiple.unwrap_or_default() && decoded_presentations.len() > 1 {
        return Ok(false);
    }

    // Each Presentation in the array MUST match the Credential Query (OID4VP 1.0, §8.1).
    let mut all_match = true;
    for decoded_presentation in decoded_presentations.iter() {
        // TODO: Check `require_cryptographic_holder_binding`
        let claims_match = matches_claims(credential_query, decoded_presentation).map_err(|source| {
            DcqlEvaluationError::ClaimPath {
                credential_query_id: credential_query.id.clone(),
                source,
            }
        })?;
        all_match &= matches_meta(&credential_query.meta, decoded_presentation) && claims_match;
    }
    Ok(all_match)
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

/// Whether `decoded_presentation` has the claims `claims` and `claim_sets` ask for. Every claims query in `claims`
/// is evaluated first, so a path that does not fit the presentation is an error whichever option it is in.
fn matches_claims(
    credential_query: &CredentialQuery,
    decoded_presentation: &JsonObject,
) -> Result<bool, ClaimPathProcessingError> {
    // If claims is absent, the Verifier is requesting no claims that are selectively disclosable;
    // the Wallet MUST return only the claims that are mandatory to present (e.g., SD-JWT and Key Binding JWT for a Credential of format IETF SD-JWT VC).
    let claims = credential_query.claims.as_deref().unwrap_or(&[]);
    if claims.is_empty() {
        return Ok(true);
    }

    let presentation_value = serde_json::Value::Object(decoded_presentation.clone());
    let satisfied = claims
        .iter()
        .map(|claim| evaluate_single_claim_query(claim, &presentation_value))
        .collect::<Result<Vec<bool>, _>>()?;

    // If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims.
    Ok(match &credential_query.claim_sets {
        None => satisfied.iter().all(|satisfied| *satisfied),

        // If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in claim_sets. The order of the options conveyed in the claim_sets array expresses the Verifier's preference for what is returned;
        // the Wallet SHOULD return the first option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT return any claims.
        Some(claim_sets) => claim_sets.iter().any(|claim_set| {
            claim_set.iter().all(|claim_id| {
                claims
                    .iter()
                    .zip(&satisfied)
                    .find(|(claim, _)| claim.id.as_ref() == Some(claim_id))
                    .is_some_and(|(_, satisfied)| *satisfied)
            })
        }),
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
        dcql::claims::{ClaimsContext, validate_claims},
        token::vp_token_validator::DecodedVpTokenBuilder,
    };
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer, ClaimValue, ClaimValues};
    use serde_json::json;

    const TESTCREDENTIAL: &str = include_str!("../tests/examples/credentials/jwt_vc.json");
    const DCQL_QUERY: &str = include_str!("../tests/examples/request/dcql_jwt_vc.json");
    const TESTCREDENTIALQUERY_WITH_SETS: &str =
        include_str!("../tests/examples/query_lang/credentials_alternatives.json");

    // The tests below that only look at the verdict use these. They shadow the functions of `super`, and fail the
    // test on an evaluation error.
    fn evaluate_dcql_query(dcql_query: &DcqlQuery, decoded_vp_token: &DecodedVpToken) -> bool {
        super::evaluate_dcql_query(dcql_query, decoded_vp_token).unwrap()
    }

    fn evaluate_credential_query(
        credential_query: &CredentialQuery,
        decoded_presentations: &DecodedPresentations,
    ) -> bool {
        super::evaluate_credential_query(credential_query, decoded_presentations).unwrap()
    }

    fn evaluate_single_claim_query(claim_query: &ClaimQuery, credential_json: &Value) -> bool {
        super::evaluate_single_claim_query(claim_query, credential_json).unwrap()
    }

    #[test]
    fn test_get_value_from_json() {
        let testing_credential: Value = serde_json::from_str(TESTCREDENTIAL).unwrap();
        let path = ClaimPathPointer::try_new(vec![
            ClaimPathElement::String("credentialSubject".to_string()),
            ClaimPathElement::String("given_name".to_string()),
        ])
        .unwrap();
        let values = path.get_values_from_json(&testing_credential["vc"]);
        assert_eq!(values, Ok(vec![json!("Max")]));
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

    fn identity_presentation() -> Value {
        json!({
            "vct": "https://credentials.example.com/identity_credential",
            "given_name": "John",
            "nationalities": ["DE", "NL"],
            "address": { "street_address": "123 Main St" }
        })
    }

    #[test]
    fn a_claim_that_is_not_in_the_presentation_does_not_satisfy_the_claims_query() {
        for path in [
            json!(["birthdate"]),
            json!(["address", "locality"]),
            json!(["nationalities", 2]),
        ] {
            let query = identity_credential_query(None, Some(json!([{ "path": path }])));
            assert_eq!(
                super::evaluate_credential_query(&query, &presentations(&[identity_presentation()])),
                Ok(false),
                "{path}"
            );
        }
    }

    #[test]
    fn a_path_that_does_not_fit_the_presentation_is_an_error() {
        for (path, source) in [
            (
                json!(["address", null]),
                ClaimPathProcessingError::NotAnArray {
                    path: serde_json::from_value(json!(["address", null])).unwrap(),
                    index: 1,
                },
            ),
            (
                json!(["nationalities", "first"]),
                ClaimPathProcessingError::NotAnObject {
                    path: serde_json::from_value(json!(["nationalities", "first"])).unwrap(),
                    index: 1,
                },
            ),
        ] {
            let query = identity_credential_query(None, Some(json!([{ "path": path }])));
            let expected = DcqlEvaluationError::ClaimPath {
                credential_query_id: "identity".parse().unwrap(),
                source,
            };
            assert_eq!(
                super::evaluate_credential_query(&query, &presentations(&[identity_presentation()])),
                Err(expected.clone())
            );

            let dcql_query: DcqlQuery = serde_json::from_value(json!({ "credentials": [query] })).unwrap();
            let decoded_vp_token = DecodedVpTokenBuilder::new()
                .insert(
                    "identity".parse().unwrap(),
                    vec![identity_presentation().as_object().unwrap().clone()],
                )
                .unwrap()
                .build();
            let error = super::evaluate_dcql_query(&dcql_query, &decoded_vp_token).unwrap_err();
            assert_eq!(error, expected);
            assert!(error.to_string().contains("`identity`"), "{error}");
        }
    }

    #[test]
    fn claim_sets_fall_back_to_the_next_option_when_a_claim_is_missing() {
        let query = identity_credential_query(
            None,
            Some(json!([
                { "id": "birthdate", "path": ["birthdate"] },
                { "id": "given_name", "path": ["given_name"] }
            ])),
        );
        let mut query = serde_json::to_value(query).unwrap();
        query["claim_sets"] = json!([["birthdate"], ["given_name"]]);
        let query: CredentialQuery = serde_json::from_value(query).unwrap();
        assert_eq!(
            super::evaluate_credential_query(&query, &presentations(&[identity_presentation()])),
            Ok(true)
        );
    }

    #[test]
    fn a_path_that_does_not_fit_is_an_error_even_in_an_option_after_a_satisfied_one() {
        let query = identity_credential_query(
            None,
            Some(json!([
                { "id": "given_name", "path": ["given_name"] },
                { "id": "street", "path": ["address", 0] }
            ])),
        );
        let mut query = serde_json::to_value(query).unwrap();
        query["claim_sets"] = json!([["given_name"], ["street"]]);
        let query: CredentialQuery = serde_json::from_value(query).unwrap();
        assert!(matches!(
            super::evaluate_credential_query(&query, &presentations(&[identity_presentation()])),
            Err(DcqlEvaluationError::ClaimPath {
                source: ClaimPathProcessingError::NotAnArray { index: 1, .. },
                ..
            })
        ));
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

    /// The query of #195: a whole OpenBadge, no claims, and a credential of another type must not match it.
    #[test]
    fn type_values_are_checked_without_claims() {
        let query: CredentialQuery = serde_json::from_value(json!({
            "id": "badge",
            "format": "vc+sd-jwt",
            "meta": { "type_values": [["VerifiableCredential", "OpenBadgeCredential"]] }
        }))
        .unwrap();

        assert!(evaluate_credential_query(
            &query,
            &presentations(&[json!({ "type": ["VerifiableCredential", "OpenBadgeCredential"] })])
        ));
        assert!(!evaluate_credential_query(
            &query,
            &presentations(&[json!({ "type": ["VerifiableCredential"] })])
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
