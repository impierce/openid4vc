use crate::{Sign, Verify};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use getset::Getters;
use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, EllipticCurveKeyParameters, EllipticCurveKeyType, Jwk, OctetKeyPairParameters,
    OctetKeyPairType,
};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation};
use serde::Serialize;
use serde::de::DeserializeOwned;
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

/// Encodes and signs a JWT whose header names the signer's key by `kid`: the key identifier of `signer` for
/// `subject_syntax_type` and the header's algorithm.
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

    sign(signer, JsonWebToken::new(header, claims).kid(kid), subject_syntax_type).await
}

/// Encodes and signs a JWT whose header carries the signer's public key as `jwk`, and no `kid`: for a JWT that
/// names its key by value, such as an OpenID4VCI key proof for an issuer that binds credentials to a JWK.
#[tracing::instrument(level = "debug", err, skip(signer, claims))]
pub async fn encode_with_jwk<C, S>(
    signer: Arc<S>,
    header: Header,
    claims: C,
    subject_syntax_type: &str,
) -> Result<String>
where
    C: Serialize,
    S: Sign + Verify + ?Sized,
{
    let algorithm = header.alg;
    let kid = signer
        .key_id(subject_syntax_type, algorithm)
        .await
        .ok_or_else(|| anyhow!("No key identifier found for signer ({algorithm:?}, {subject_syntax_type})"))?;
    let jwk = public_jwk(&signer.public_key(&kid).await?, algorithm)?;

    tracing::debug!(?algorithm, %subject_syntax_type, "Encoding and signing JWT with a `jwk` header");

    let header = Header {
        kid: None,
        jwk: Some(jwk),
        ..header
    };
    sign(signer, JsonWebToken::new(header, claims), subject_syntax_type).await
}

/// The public key a [`Verify`] returns, as a JWK: the 32 bytes of an Ed25519 key for `EdDSA`, the uncompressed SEC1
/// point of a P-256 key for `ES256`. These are the forms [`decode`] verifies with.
pub fn public_jwk(public_key: &[u8], algorithm: Algorithm) -> Result<Jwk> {
    let algorithm_parameters = match (algorithm, public_key) {
        (Algorithm::EdDSA, key) if key.len() == 32 => AlgorithmParameters::OctetKeyPair(OctetKeyPairParameters {
            key_type: OctetKeyPairType::OctetKeyPair,
            curve: EllipticCurve::Ed25519,
            x: URL_SAFE_NO_PAD.encode(key),
        }),
        (Algorithm::ES256, [0x04, coordinates @ ..]) if coordinates.len() == 64 => {
            AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x: URL_SAFE_NO_PAD.encode(&coordinates[..32]),
                y: URL_SAFE_NO_PAD.encode(&coordinates[32..]),
            })
        }
        (Algorithm::EdDSA | Algorithm::ES256, key) => {
            return Err(anyhow!(
                "A public key of {} bytes is not one {algorithm:?} signs with",
                key.len()
            ));
        }
        _ => return Err(anyhow!("Unsupported algorithm {algorithm:?}")),
    };
    Ok(Jwk {
        common: Default::default(),
        algorithm: algorithm_parameters,
    })
}

async fn sign<C, S>(signer: Arc<S>, jwt: JsonWebToken<C>, subject_syntax_type: &str) -> Result<String>
where
    C: Serialize,
    S: Sign + ?Sized,
{
    let algorithm = jwt.header.alg;
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
        Verify,
        test_utils::{MockVerifier, TestSubject},
    };
    use serde_json::{Value, json};

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

    #[tokio::test]
    async fn encode_with_jwk_names_the_key_by_value() {
        let claims = json!({ "aud": "https://issuer.example", "iat": 1593436422 });
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();
        let encoded = encode_with_jwk(
            Arc::new(subject),
            Header::new(Algorithm::EdDSA),
            claims.clone(),
            "did:test",
        )
        .await
        .unwrap();

        // "jwk: ... It MUST NOT be present if kid is present" (OpenID4VCI 1.0, Appendix F.1).
        let header = jsonwebtoken::decode_header(&encoded).unwrap();
        assert_eq!(header.kid, None);
        let jwk = serde_json::to_value(header.jwk.unwrap()).unwrap();
        let public_key = MockVerifier::new().public_key("key_id").await.unwrap();
        assert_eq!(
            jwk,
            json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(&public_key) })
        );

        // The signature verifies with the key the header carries.
        let from_header = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
        let decoded: Value = decode(&encoded, from_header, Algorithm::EdDSA).unwrap();
        assert_eq!(decoded, claims);
    }

    #[test]
    fn public_jwk_of_a_p256_key() {
        // The key of RFC 7515, Appendix A.3.1.
        let x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        let y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
        let point = [
            vec![0x04],
            URL_SAFE_NO_PAD.decode(x).unwrap(),
            URL_SAFE_NO_PAD.decode(y).unwrap(),
        ]
        .concat();

        let jwk = public_jwk(&point, Algorithm::ES256).unwrap();

        assert_eq!(
            serde_json::to_value(jwk).unwrap(),
            json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y })
        );
    }

    #[test]
    fn public_jwk_refuses_a_key_that_does_not_fit_the_algorithm() {
        // A compressed point, an Ed25519 key for ES256, and an algorithm without a JWK form here.
        assert!(public_jwk(&[0x02; 33], Algorithm::ES256).is_err());
        assert!(public_jwk(&[0x00; 32], Algorithm::ES256).is_err());
        assert!(public_jwk(&[0x00; 31], Algorithm::EdDSA).is_err());
        assert!(public_jwk(&[0x00; 32], Algorithm::RS256).is_err());
    }
}
