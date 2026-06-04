use crate::utils::jwt::{get_unverified_jwt_claims, sd_jwt_to_jwt};
use jsonwebtoken::decode_header;

/// Extract the `kid` from a JWT header as a DID URL.
///
/// If the `kid` is a relative DID fragment such as `#key-1`, this function
/// prefixes it with the unverified `iss` claim from the JWT payload to produce
/// an absolute DID URL.
///
/// Returns an error if the JWT header cannot be decoded, if `kid` is missing,
/// or if a relative `kid` cannot be expanded because `iss` is missing or not a string.
pub fn extract_normalized_did_kid_from_jwt(jwt: &str) -> Result<String, anyhow::Error> {
    let jwt = sd_jwt_to_jwt(jwt);

    let jwt_header = decode_header(jwt).map_err(|e| anyhow::anyhow!("Failed to decode JWT header: {e}"))?;
    let mut key_id = jwt_header
        .kid
        .ok_or_else(|| anyhow::anyhow!("Missing 'kid' in JWT header"))?;

    if key_id.starts_with('#') {
        let claims = get_unverified_jwt_claims(&serde_json::json!(jwt))?;
        let iss = claims
            .get("iss")
            .ok_or_else(|| anyhow::anyhow!("Missing 'iss' claim"))?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("'iss' claim is not a string"))?;

        key_id = format!("{iss}{key_id}");
    }

    Ok(key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_key_id_with_relative_reference() {
        // JWT with relative key_id (starts with '#')
        let jwt =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IiNteWtleSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        let result = extract_normalized_did_kid_from_jwt(jwt);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "did:example:issuer#mykey");
    }

    #[test]
    fn resolve_key_id_with_absolute_reference() {
        // JWT with absolute key_id (doesn't start with '#')
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmlzc3VlciNteWtleSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        let result = extract_normalized_did_kid_from_jwt(jwt);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "did:example:issuer#mykey");
    }

    #[test]
    fn resolve_key_id_missing_kid() {
        // JWT without kid in header
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        let result = extract_normalized_did_kid_from_jwt(jwt);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_key_id_missing_iss_claim() {
        // JWT with relative key_id but missing 'iss' claim
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IiNteWtleSJ9.e30.signature";
        let result = extract_normalized_did_kid_from_jwt(jwt);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_key_id_iss_not_string() {
        // JWT with relative key_id but 'iss' claim is not a string
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IiNteWtleSJ9.eyJpc3MiOjEyMzQ1fQ.signature";
        let result = extract_normalized_did_kid_from_jwt(jwt);
        assert!(result.is_err());
    }
}
