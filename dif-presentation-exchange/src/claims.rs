use crate::presentation_definition::{ClaimPathElement, ClaimQuery, ClaimValue};

use validator::ValidationError;

#[derive(Debug)]
pub struct ClaimsContext<'a> {
    pub claim_sets: &'a Option<Vec<Vec<String>>>,
}

pub fn validate_claims(claims: &[ClaimQuery], ctx: &ClaimsContext) -> Result<(), ValidationError> {
    if let Some(claim_sets) = ctx.claim_sets {
        validate_claims_with_sets(claims, claim_sets)?;
    }

    Ok(())
}

pub fn validate_claims_with_sets(claims: &[ClaimQuery], claim_sets: &[Vec<String>]) -> Result<(), ValidationError> {
    if claims.is_empty() {
        return Err(
            ValidationError::new("empty_claims").with_message("Claims cannot be empty when claim_sets is used".into())
        );
    }

    for (i, claim) in claims.iter().enumerate() {
        if claim.id.is_none() {
            return Err(ValidationError::new("missing_claim_id")
                .with_message(format!("Claim ID is missing at index {}", i).into()));
        }
    }

    let claim_ids: Vec<&String> = claims.iter().filter_map(|c| c.id.as_ref()).collect();

    for (i, set) in claim_sets.iter().enumerate() {
        for (j, id) in set.iter().enumerate() {
            if !claim_ids.contains(&id) {
                return Err(ValidationError::new("invalid_claim_id")
                    .with_message(format!("Claim ID '{}' not found in claims at claim_set[{}][{}]", id, i, j).into()));
            }
        }
    }
    Ok(())
}

pub fn validate_claim_path(path: &[ClaimPathElement]) -> Result<(), ValidationError> {
    if path.is_empty() {
        return Err(ValidationError::new("empty_claim_path").with_message("Claim path cannot be empty".into()));
    }
    Ok(())
}
pub fn validate_claim_values(values: &[ClaimValue]) -> Result<(), ValidationError> {
    if values.is_empty() {
        return Err(ValidationError::new("empty_claim_values").with_message("Claim values cannot be empty".into()));
    }
    Ok(())
}
