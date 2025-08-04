use super::dcql_query::ClaimQuery;
use validator::ValidationError;

#[derive(Debug)]
pub struct ClaimsContext<'a> {
    pub claim_sets: &'a Option<Vec<Vec<String>>>,
}

pub fn validate_claims(claims: &[ClaimQuery], ctx: &ClaimsContext) -> Result<(), ValidationError> {
    if let Some(claim_sets) = ctx.claim_sets {
        validate_claims_with_sets(claims, claim_sets)?;
    } else {
        // When claim_sets is not present, validate that IDs are unique if they exist
        validate_claims_without_sets(claims)?;
    }
    Ok(())
}

pub fn validate_claims_with_sets(claims: &[ClaimQuery], claim_sets: &[Vec<String>]) -> Result<(), ValidationError> {
    if claims.is_empty() {
        return Err(
            ValidationError::new("empty_claims").with_message("Claims cannot be empty when claim_sets is used".into())
        );
    }

    // When claim_sets is present, each claim is required to have an ID.
    for (i, claim) in claims.iter().enumerate() {
        if claim.id.is_none() {
            return Err(ValidationError::new("missing_claim_id").with_message(
                format!("Claim ID is required when claim_sets is present, missing at index {i}").into(),
            ));
        }
    }

    // IDs within claims must be unique - validate
    let mut seen_ids = std::collections::HashSet::new();
    for (i, claim) in claims.iter().enumerate() {
        if let Some(id) = &claim.id {
            if !seen_ids.insert(id) {
                return Err(ValidationError::new("duplicate_claim_id")
                    .with_message(format!("Duplicate claim ID '{id}' found at index {i}").into()));
            }
        }
    }

    // Collect claim IDs for validation against claim_sets
    let claim_ids: Vec<&String> = claims.iter().filter_map(|c| c.id.as_ref()).collect();

    // Validate that all IDs in claim_sets exist in claims
    for (i, set) in claim_sets.iter().enumerate() {
        for (j, id) in set.iter().enumerate() {
            if !claim_ids.contains(&id) {
                return Err(ValidationError::new("invalid_claim_id")
                    .with_message(format!("Claim ID '{id}' not found in claims at claim_set[{i}][{j}]").into()));
            }
        }
    }

    Ok(())
}

pub fn validate_claims_without_sets(claims: &[ClaimQuery]) -> Result<(), ValidationError> {
    // When claim_sets is not present, IDs are optional but must be unique if they exist
    let mut seen_ids = std::collections::HashSet::new();

    for (i, claim) in claims.iter().enumerate() {
        if let Some(id) = &claim.id {
            // Validate ID format (alphanumeric, underscore, or hyphen characters)
            if !id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                return Err(ValidationError::new("invalid_claim_id_format")
                    .with_message(format!("Claim ID '{id}' at index {i} contains invalid characters. Only alphanumeric, underscore, and hyphen characters are allowed").into()));
            }

            if id.is_empty() {
                return Err(ValidationError::new("empty_claim_id")
                    .with_message(format!("Claim ID cannot be empty at index {i}").into()));
            }

            if !seen_ids.insert(id) {
                return Err(ValidationError::new("duplicate_claim_id")
                    .with_message(format!("Duplicate claim ID '{id}' found at index {i}").into()));
            }
        }
    }

    Ok(())
}
