use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::decode_header;

/// Get the claims from a JWT without performing validation.
pub fn get_unverified_jwt_claims(jwt: &serde_json::Value) -> Result<serde_json::Value, anyhow::Error> {
    jwt.as_str()
        .and_then(|string| string.splitn(3, '.').collect::<Vec<&str>>().get(1).cloned())
        .and_then(|payload| {
            URL_SAFE_NO_PAD
                .decode(payload)
                .ok()
                .and_then(|payload_bytes| serde_json::from_slice::<serde_json::Value>(&payload_bytes).ok())
        })
        .ok_or_else(|| anyhow::anyhow!("Failed to decode JWT claims"))
}

/// If the input is an SD-JWT, extract the JWT part. Otherwise, return the input as is.
fn sd_jwt_to_jwt(sd_jwt: &str) -> &str {
    sd_jwt.split_once('~').map(|(jwt, _)| jwt).unwrap_or(sd_jwt)
}

/// This function resolves the key ID from the JWT header, and makes it absolute if it's a relative reference (starts
/// with '#') by prepending the 'iss' claim from the JWT payload.
pub fn resolve_key_id(jwt: &str) -> Result<String, anyhow::Error> {
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
    use serde_json::json;

    #[test]
    fn get_unverified_jwt_claims_successfully_gets_claims() {
        let jwt = json!("eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2toUDQzTENTWGFqM1NRQm92eTF1RTJuWHZTQm5SUFdaMndoUExxblo4UGdEI3o2TWtraFA0M0xDU1hhajNTUUJvdnkxdUUyblh2U0JuUlBXWjJ3aFBMcW5aOFBnRCJ9.eyJpc3MiOiJodHRwOi8vMTkyLjE2OC4xLjEyNzo5MDkwLyIsInN1YiI6ImRpZDprZXk6ejZNa2cxWFhHVXFma2hBS1Uxa1ZkMVBtdzZVRWoxdnhpTGoxeGM5MU1CejVvd05ZIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjAsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlBlcnNvbmFsSW5mb3JtYXRpb24iXSwiaXNzdWFuY2VEYXRlIjoiMjAyMi0wMS0wMVQwMDowMDowMFoiLCJpc3N1ZXIiOiJodHRwOi8vMTkyLjE2OC4xLjEyNzo5MDkwLyIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rZzFYWEdVcWZraEFLVTFrVmQxUG13NlVFajF2eGlMajF4YzkxTUJ6NW93TlkiLCJnaXZlbk5hbWUiOiJGZXJyaXMiLCJmYW1pbHlOYW1lIjoiQ3JhYm1hbiIsImVtYWlsIjoiZmVycmlzLmNyYWJtYW5AY3JhYm1haWwuY29tIiwiYmlydGhkYXRlIjoiMTk4NS0wNS0yMSJ9fX0.Yl841U5BwWgctX5vF5Zi8SYCEQpxFqEs8_J8KrX9D_mOwL-IRmP64BeQZvnKeAdcOoYGn6CyciV51_amdPNQBw");

        assert_eq!(
            get_unverified_jwt_claims(&jwt).unwrap(),
            json!({
              "iss": "http://192.168.1.127:9090/",
              "sub": "did:key:z6Mkg1XXGUqfkhAKU1kVd1Pmw6UEj1vxiLj1xc91MBz5owNY",
              "exp": 9999999999i64,
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
            })
        );
    }

    #[test]
    fn resolve_key_id_with_relative_reference() {
        // JWT with relative key_id (starts with '#')
        let jwt =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IiNteWtleSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        let result = resolve_key_id(jwt);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "did:example:issuer#mykey");
    }

    #[test]
    fn resolve_key_id_with_absolute_reference() {
        // JWT with absolute key_id (doesn't start with '#')
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOmlzc3VlciNteWtleSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        let result = resolve_key_id(jwt);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "did:example:issuer#mykey");
    }

    #[test]
    fn resolve_key_id_missing_kid() {
        // JWT without kid in header
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature";
        let result = resolve_key_id(jwt);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_key_id_missing_iss_claim() {
        // JWT with relative key_id but missing 'iss' claim
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IiNteWtleSJ9.e30.signature";
        let result = resolve_key_id(jwt);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_key_id_iss_not_string() {
        // JWT with relative key_id but 'iss' claim is not a string
        let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6IiNteWtleSJ9.eyJpc3MiOjEyMzQ1fQ.signature";
        let result = resolve_key_id(jwt);
        assert!(result.is_err());
    }
}
