use super::dcql_query::ClaimQuery;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DcqlClaimsError {
    #[error("Claims cannot be empty when claim_sets is used")]
    EmptyClaims,
    #[error("Claim ID is required when claim_sets is present, missing at index {0}")]
    MissingClaimId(usize),
    #[error("Claim ID '{0}' at index {1} contains invalid characters. Only alphanumeric, underscore, and hyphen characters are allowed")]
    InvalidClaimIdFormat(String, usize),
    #[error("Claim ID cannot be empty at index {0}")]
    EmptyClaimId(usize),
    #[error("Duplicate claim ID '{0}' found at index {1}")]
    DuplicateClaimId(String, usize),
    #[error("Claim ID '{0}' not found in claims at claim_set[{1}][{2}]")]
    InvalidClaimIdReference(String, usize, usize),
}

#[derive(Debug)]
pub struct ClaimsContext<'a> {
    pub claim_sets: &'a Option<Vec<Vec<String>>>,
}

pub fn validate_claims(claims: &[ClaimQuery], ctx: &ClaimsContext) -> Result<(), DcqlClaimsError> {
    tracing::debug!(
        claim_count = claims.len(),
        has_claim_sets = ctx.claim_sets.is_some(),
        "Validating DCQL claims"
    );
    if let Some(claim_sets) = ctx.claim_sets {
        validate_claims_with_sets(claims, claim_sets)?;
    } else {
        // When claim_sets is not present, validate that IDs are unique if they exist
        validate_claims_without_sets(claims)?;
    }
    Ok(())
}

#[tracing::instrument(level = "debug", err, skip(claims, claim_sets))]
pub fn validate_claims_with_sets(claims: &[ClaimQuery], claim_sets: &[Vec<String>]) -> Result<(), DcqlClaimsError> {
    if claims.is_empty() {
        return Err(DcqlClaimsError::EmptyClaims);
    }

    // When claim_sets is present, each claim is required to have an ID.
    for (i, claim) in claims.iter().enumerate() {
        if claim.id.is_none() {
            return Err(DcqlClaimsError::MissingClaimId(i));
        }
    }

    // Validate the claim ID format and uniqueness.
    validate_claim_ids(claims)?;

    let claim_ids: Vec<&String> = claims.iter().filter_map(|c| c.id.as_ref()).collect();

    // Validate that all IDs in claim_sets exist in claims
    validate_claims_sets_references(&claim_ids, claim_sets)?;

    Ok(())
}

#[tracing::instrument(level = "debug", err, skip(claims))]
pub fn validate_claims_without_sets(claims: &[ClaimQuery]) -> Result<(), DcqlClaimsError> {
    // When claim_sets is not present, IDs are optional but must be unique if they exist
    validate_claim_ids(claims)?;

    Ok(())
}

/// Validates that the claim IDs in the claims are unique and follow the required format.
fn validate_claim_ids(claims: &[ClaimQuery]) -> Result<(), DcqlClaimsError> {
    let mut seen_ids = std::collections::HashSet::new();

    for (i, claim) in claims.iter().enumerate() {
        if let Some(id) = &claim.id {
            if !is_valid_claim_id_format(id) {
                return Err(DcqlClaimsError::InvalidClaimIdFormat(id.clone(), i));
            }
            if id.is_empty() {
                return Err(DcqlClaimsError::EmptyClaimId(i));
            }
            if !seen_ids.insert(id) {
                return Err(DcqlClaimsError::DuplicateClaimId(id.clone(), i));
            }
        }
    }
    Ok(())
}

/// Validates that claim IDs in claim_sets reference valid claims.
fn validate_claims_sets_references(claim_ids: &[&String], claim_sets: &[Vec<String>]) -> Result<(), DcqlClaimsError> {
    for (i, set) in claim_sets.iter().enumerate() {
        for (j, id) in set.iter().enumerate() {
            if !claim_ids.contains(&id) {
                return Err(DcqlClaimsError::InvalidClaimIdReference(id.clone(), i, j));
            }
        }
    }
    Ok(())
}

fn is_valid_claim_id_format(id: &str) -> bool {
    !id.is_empty() && id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcql::dcql_query::DcqlQuery;
    use lazy_static::lazy_static;

    lazy_static! {
        pub static ref VALID_QUERY: serde_json::Value = serde_json::json!(
                  {
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                {"id": "a", "path": ["last_name"]},
                {"id": "b", "path": ["postal_code"]},
                {"id": "c", "path": ["locality"]},
                {"id": "d", "path": ["region"]},
                {"id": "e", "path": ["date_of_birth"]}
              ],
              "claim_sets": [
                ["a", "c", "d", "e"],
                ["a", "b", "e"]
              ]
            }
          ]
        }
              );
        pub static ref INVALID_QUERY_WITH_SETS_DUPLICATE_ID: serde_json::Value = serde_json::json!({
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                {"id": "a", "path": ["last_name"]},
                {"id": "a", "path": ["postal_code"]},
                { "id": "a", "path": ["locality"]},
                {"id": "d", "path": ["region"]},
                {"id": "e", "path": ["date_of_birth"]}
              ],
              "claim_sets": [
                ["a", "c", "d", "e"],
                ["a", "b", "e"]
              ]
            }
          ]
        });
        pub static ref INVALID_QUERY_WITH_SETS_MISSING_ID: serde_json::Value = serde_json::json!({
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                {"path": ["last_name"]},
                {"id": "b", "path": ["postal_code"]},
                { "path": ["locality"]},
                {"id": "d", "path": ["region"]},
                {"id": "e", "path": ["date_of_birth"]}
              ],
              "claim_sets": [
                ["a", "c", "d", "e"],
                ["a", "b", "e"]
              ]
            }
          ]
        });
        pub static ref INVALID_QUERY_WITH_SETS_NONEXISTENT_ID: serde_json::Value = serde_json::json!({
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                {"id": "a", "path": ["last_name"]},
                {"id": "b", "path": ["postal_code"]},
                { "id": "c", "path": ["locality"]},
                {"id": "d", "path": ["region"]},
                {"id": "e", "path": ["date_of_birth"]}
              ],
              "claim_sets": [
                ["z", "c", "d", "e"],
                ["a", "b", "e"]
              ]
            }
          ]
        });
        pub static ref INVALID_QUERY_WITHOUT_SETS_INVALID_ID_FORMAT: serde_json::Value = serde_json::json!({
          "credentials": [
            {
              "id": "pid",
              "format": "dc+sd-jwt",
              "meta": {
                "vct_values": [ "https://credentials.example.com/identity_credential" ]
              },
              "claims": [
                {"id": "!", "path": ["last_name"]},
                {"id": "b&", "path": ["postal_code"]},
                { "id": "c", "path": ["locality"]},
                {"id": "d", "path": ["region"]},
                {"id": "e", "path": ["date_of_birth"]}
              ],
            }
          ]
        });
    }

    #[test]
    fn test_validate_claims_valid() {
        let dcql_query: DcqlQuery = serde_json::from_value(VALID_QUERY.clone()).unwrap();
        let credential = &dcql_query.credentials[0];

        let ctx = ClaimsContext {
            claim_sets: &credential.claim_sets,
        };

        let result = validate_claims(credential.claims.as_deref().unwrap_or(&[]), &ctx);
        assert!(result.is_ok(), "Valid claims should pass validation");
    }

    #[test]
    fn test_validate_claims_with_sets_duplicate_id() {
        let dcql_query: DcqlQuery = serde_json::from_value(INVALID_QUERY_WITH_SETS_DUPLICATE_ID.clone()).unwrap();
        let credential = &dcql_query.credentials[0];

        let ctx = ClaimsContext {
            claim_sets: &credential.claim_sets,
        };

        let result = validate_claims(credential.claims.as_deref().unwrap_or(&[]), &ctx);
        assert!(result.is_err(), "Duplicate IDs found");
        let err = result.unwrap_err();
        assert!(matches!(err, DcqlClaimsError::DuplicateClaimId(..)));
    }

    #[test]
    fn test_validate_claims_with_sets_missing_id() {
        let dcql_query: DcqlQuery = serde_json::from_value(INVALID_QUERY_WITH_SETS_MISSING_ID.clone()).unwrap();
        let credential = &dcql_query.credentials[0];

        let ctx = ClaimsContext {
            claim_sets: &credential.claim_sets,
        };

        let result = validate_claims(credential.claims.as_deref().unwrap_or(&[]), &ctx);
        assert!(result.is_err(), "IDs are missing but claim_sets are present");
        let err = result.unwrap_err();
        assert!(matches!(err, DcqlClaimsError::MissingClaimId(..)));
    }

    #[test]
    fn test_validate_claims_with_sets_nonexistent_id() {
        let dcql_query: DcqlQuery = serde_json::from_value(INVALID_QUERY_WITH_SETS_NONEXISTENT_ID.clone()).unwrap();
        let credential = &dcql_query.credentials[0];

        let ctx = ClaimsContext {
            claim_sets: &credential.claim_sets,
        };

        let result = validate_claims(credential.claims.as_deref().unwrap_or(&[]), &ctx);
        assert!(result.is_err(), "Nonexistent ID found in claim_sets");
        let err = result.unwrap_err();
        assert!(matches!(err, DcqlClaimsError::InvalidClaimIdReference(..)));
    }

    #[test]
    fn test_validate_claims_without_sets_invalid_format() {
        let dcql_query: DcqlQuery =
            serde_json::from_value(INVALID_QUERY_WITHOUT_SETS_INVALID_ID_FORMAT.clone()).unwrap();
        let credential = &dcql_query.credentials[0];

        let ctx = ClaimsContext {
            claim_sets: &credential.claim_sets,
        };

        let result: Result<(), DcqlClaimsError> = validate_claims(credential.claims.as_deref().unwrap_or(&[]), &ctx);
        assert!(result.is_err(), "Invalid ID format");
        let err = result.unwrap_err();
        assert!(matches!(err, DcqlClaimsError::InvalidClaimIdFormat(..)));
    }
}
