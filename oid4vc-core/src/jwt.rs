use crate::{
    credential_status_verifier::CredentialStatusVerifier, verification_material_resolver::VerificationMaterialResolver,
    Sign,
};
use anyhow::{anyhow, Result};
use getset::Getters;
use jsonwebtoken::{decode_header, jwk::Jwk as JsonWebTokenJwk, Algorithm, DecodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;

use identity_core::convert::{FromJson as _, ToJson as _};
use identity_credential::credential::Jwt;
use identity_verification::jws::Decoder;
use serde_json::Value;

#[derive(Debug, Serialize, Getters)]
pub struct JsonWebToken<C>
where
    C: Serialize,
{
    #[getset(get = "pub")]
    pub header: Header,
    pub payload: C,
}

impl<C> JsonWebToken<C>
where
    C: Serialize,
{
    pub fn new(header: Header, payload: C) -> Self {
        JsonWebToken { header, payload }
    }

    pub fn kid(mut self, kid: String) -> Self {
        self.header.kid = Some(kid);
        self
    }
}

pub fn extract_header(jwt: &str) -> Result<(String, Algorithm)> {
    let header = jsonwebtoken::decode_header(jwt)?;
    if let Some(kid) = header.kid {
        Ok((kid, header.alg))
    } else {
        Err(anyhow!("No key identifier found in the header."))
    }
}

pub fn decode<T>(jwt: &str, public_key: Vec<u8>, algorithm: Algorithm) -> Result<T>
where
    T: DeserializeOwned,
{
    let decoding_key = match algorithm {
        Algorithm::EdDSA => DecodingKey::from_ed_der(public_key.as_slice()),
        Algorithm::ES256 => DecodingKey::from_ec_der(public_key.as_slice()),
        _ => return Err(anyhow!("Unsupported algorithm.")),
    };

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    Ok(jsonwebtoken::decode::<T>(jwt, &decoding_key, &validation)?.claims)
}

pub async fn encode<C, S>(signer: Arc<S>, header: Header, claims: C, subject_syntax_type: &str) -> Result<String>
where
    C: Serialize,
    S: Sign + ?Sized,
{
    let algorithm = header.alg;
    let kid = signer
        .key_id(subject_syntax_type, algorithm)
        .await
        .ok_or(anyhow!("No key identifier found."))?;

    let jwt = JsonWebToken::new(header, claims).kid(kid);

    let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

    let proof_value = signer.sign(&message, subject_syntax_type, algorithm).await?;
    let signature = base64_url::encode(proof_value.as_slice());
    let message = [message, signature].join(".");
    Ok(message)
}

pub fn base64_url_encode<T>(value: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(base64_url::encode(serde_json::to_vec(value)?.as_slice()))
}

/// Validate a credential JWT: resolve the issuer's public key, verify the
/// signature, extract the `vc` claim, and optionally check credential status.
/// This fn expects the JWT to have the credential in the `vc` claim as prescribed by the jwt_vc_json format as defined here: https://www.w3.org/TR/vc-data-model-1.1/#jwt-encoding
pub async fn validate_credential_jwt(
    resolver: &impl VerificationMaterialResolver,
    credential_status_verifier: &impl CredentialStatusVerifier,
    credential_jwt: &Jwt,
) -> Result<Value> {
    let validation_item = Decoder::new()
        .decode_compact_serialization(credential_jwt.as_str().as_bytes(), None)
        .map_err(|e| anyhow!("JWS decoding error: {e}"))?;

    let kid_str = validation_item
        .kid()
        .ok_or_else(|| anyhow!("Missing KID in JWT header"))?;

    // TODO: verify whether issuer is trusted (through `trusted_authorities`).

    let public_key_jwk = resolver
        .resolve_public_key(kid_str)
        .await
        .map_err(|e| anyhow!("Verification material resolution error: {e}"))?;

    let decoding_key = convert_iota_jwk_to_decoding_key(&public_key_jwk)
        .ok_or_else(|| anyhow!("Failed to convert JWK to DecodingKey"))?;

    let jwt_header = decode_header(credential_jwt.as_str()).map_err(|e| anyhow!("JWT header decoding error: {e}"))?;

    // The below validation settings are disabled because since different specs require different claims and this fn needs to be agnostic of those specs.
    let mut validation = Validation::new(jwt_header.alg);
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let jwt_data = jsonwebtoken::decode::<Value>(credential_jwt.as_str(), &decoding_key, &validation)
        .map_err(|e| anyhow!("JWT validation error: {e}"))?;

    let credential = jwt_data
        .claims
        .get("vc")
        .ok_or_else(|| anyhow!("JWT is missing the `vc` claim"))?
        .clone();

    if let Some(status_value) = jwt_data.claims.get("status").cloned() {
        credential_status_verifier
            .check_credential_status(status_value)
            .await
            .map_err(|_| anyhow!("Credential status is invalid"))?;
    }

    Ok(credential)
}

/// Convert an `identity_jose` JWK into a `jsonwebtoken` [`DecodingKey`].
fn convert_iota_jwk_to_decoding_key(public_key: &identity_jose::jwk::Jwk) -> Option<DecodingKey> {
    public_key
        .to_json()
        .ok()
        .and_then(|json| JsonWebTokenJwk::from_json(&json).ok())
        .and_then(|jwk| DecodingKey::from_jwk(&jwk).ok())
}

#[cfg(feature = "test-utils")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{MockVerifier, TestSubject},
        Verify,
    };
    use serde_json::{json, Value};

    #[tokio::test]
    async fn test_encode() {
        let claims = json!({
            "iss": "did:example:123",
            "sub": "did:example:123",
            "aud": "did:example:456",
            "exp": 9223372036854775807i64,
            "iat": 1593436422,
            "nonce": "nonce",
        });
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();
        let encoded = encode(Arc::new(subject), Header::new(Algorithm::EdDSA), claims, "did:test")
            .await
            .unwrap();

        let verifier = MockVerifier::new();
        let (kid, algorithm) = extract_header(&encoded).unwrap();
        let public_key = verifier.public_key(&kid).await.unwrap();
        let decoded: Value = decode(&encoded, public_key, algorithm).unwrap();

        assert_eq!(
            decoded,
            json!({
                "iss": "did:example:123",
                "sub": "did:example:123",
                "aud": "did:example:456",
                "exp": 9223372036854775807i64,
                "iat": 1593436422,
                "nonce": "nonce",
            })
        )
    }
}
