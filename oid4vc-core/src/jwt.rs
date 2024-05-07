use crate::Sign;
use anyhow::{anyhow, Result};
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
    let key = DecodingKey::from_ed_der(public_key.as_slice());
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    Ok(jsonwebtoken::decode::<T>(jwt, &key, &validation)?.claims)
}

pub async fn encode<C, S>(signer: Arc<S>, header: Header, claims: C, subject_syntax_type: &str) -> Result<String>
where
    C: Serialize,
    S: Sign + ?Sized,
{
    let kid = signer
        .key_id(subject_syntax_type)
        .await
        .ok_or(anyhow!("No key identifier found."))?;

    let jwt = JsonWebToken::new(header, claims).kid(kid);

    let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

    let proof_value = signer.sign(&message, subject_syntax_type).await?;
    let signature = base64_url::encode(proof_value.as_slice());
    let message = [message, signature].join(".");
    Ok(message)
}

fn base64_url_encode<T>(value: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(base64_url::encode(serde_json::to_vec(value)?.as_slice()))
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
