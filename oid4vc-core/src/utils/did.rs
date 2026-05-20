use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::decode_header;

// TODO: actually validate the JWT!
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

fn sd_jwt_to_jwt(sd_jwt: &str) -> &str {
    sd_jwt.split_once('~').map(|(jwt, _)| jwt).unwrap_or(sd_jwt)
}

/// This function resolves the key ID from the JWT header, and makes it absolute if it's a relative reference (starts with '#') by prepending the 'iss' claim from the JWT payload.
pub fn resolve_key_id(jwt: &str) -> Result<String, anyhow::Error> {
    let jwt = sd_jwt_to_jwt(jwt);

    let jwt_header = decode_header(jwt).unwrap();
    // let jwt_header = decode_header(jwt).map_err(|_| anyhow::anyhow!("Failed to decode JWT header"))?;
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
