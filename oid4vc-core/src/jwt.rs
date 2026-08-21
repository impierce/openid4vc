use crate::Sign;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use getset::Getters;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::sync::Arc;

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

#[tracing::instrument(level = "trace", err, skip(jwt))]
pub fn extract_header(jwt: &str) -> Result<(String, Algorithm)> {
    let header = jsonwebtoken::decode_header(jwt)?;
    if let Some(kid) = header.kid {
        tracing::trace!(algorithm = ?header.alg, %kid, "Extracted JWT header");
        Ok((kid, header.alg))
    } else {
        Err(anyhow!("No key identifier found in the header."))
    }
}

#[tracing::instrument(level = "debug", err, skip(jwt, public_key))]
pub fn decode<T>(jwt: &str, public_key: Vec<u8>, algorithm: Algorithm) -> Result<T>
where
    T: DeserializeOwned,
{
    let decoding_key = match algorithm {
        Algorithm::EdDSA => DecodingKey::from_ed_der(public_key.as_slice()),
        Algorithm::ES256 => DecodingKey::from_ec_der(public_key.as_slice()),
        _ => return Err(anyhow!("Unsupported algorithm {algorithm:?}")),
    };

    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    Ok(jsonwebtoken::decode::<T>(jwt, &decoding_key, &validation)?.claims)
}

#[tracing::instrument(level = "debug", err, skip(signer, claims))]
pub async fn encode<C, S>(signer: Arc<S>, header: Header, claims: C, subject_syntax_type: &str) -> Result<String>
where
    C: Serialize,
    S: Sign + ?Sized,
{
    let algorithm = header.alg;
    let kid = signer
        .key_id(subject_syntax_type, algorithm)
        .await
        .ok_or_else(|| anyhow!("No key identifier found for signer ({algorithm:?}, {subject_syntax_type})"))?;

    tracing::debug!(?algorithm, %kid, %subject_syntax_type, "Encoding and signing JWT");

    let jwt = JsonWebToken::new(header, claims).kid(kid);

    let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

    let proof_value = signer.sign(&message, subject_syntax_type, algorithm).await?;
    let signature = URL_SAFE_NO_PAD.encode(proof_value.as_slice());
    let message = [message, signature].join(".");
    Ok(message)
}

pub fn base64_url_encode<T>(value: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?.as_slice()))
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
