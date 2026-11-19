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

    verify(jwt, &decoding_key, algorithm)
}

/// The algorithms whose public keys [`public_jwk`] writes as a JWK and [`decode_with_jwk`] verifies with.
pub const JWK_ALGORITHMS: [Algorithm; 2] = [Algorithm::EdDSA, Algorithm::ES256];

/// Verifies a JWT whose header names its key by value (`jwk`, and no `kid`) with that key, and returns the claims
/// together with the key.
///
/// The signature shows that the sender holds the key, not whose key it is. That is what an OpenID4VCI key proof is
/// for; never use this for a JWT whose signer has to be identified.
#[tracing::instrument(level = "debug", err, skip(jwt))]
pub fn decode_with_jwk<T>(jwt: &str) -> Result<(T, Jwk)>
where
    T: DeserializeOwned,
{
    let header = jsonwebtoken::decode_header(jwt)?;
    if header.kid.is_some() {
        return Err(anyhow!("A JWT that names its key by `jwk` must not have a `kid`."));
    }
    ensure_no_critical_extension(jwt)?;
    let jwk = header.jwk.ok_or_else(|| anyhow!("No `jwk` found in the header."))?;

    // The key has to be one the algorithm signs with, in the one form a JWK has for it: `jsonwebtoken` joins the
    // coordinates of a P-256 key without looking at their lengths, so a key with them split unevenly would verify
    // and be returned as a JWK no other consumer accepts.
    let algorithm = header.alg;
    let is_key_of_the_algorithm = match (algorithm, &jwk.algorithm) {
        (Algorithm::EdDSA, AlgorithmParameters::OctetKeyPair(key)) => {
            key.curve == EllipticCurve::Ed25519 && decodes_to_32_bytes(&key.x)
        }
        (Algorithm::ES256, AlgorithmParameters::EllipticCurve(key)) => {
            key.curve == EllipticCurve::P256 && decodes_to_32_bytes(&key.x) && decodes_to_32_bytes(&key.y)
        }
        (Algorithm::EdDSA | Algorithm::ES256, _) => false,
        _ => return Err(anyhow!("Unsupported algorithm {algorithm:?}")),
    };
    if !is_key_of_the_algorithm {
        return Err(anyhow!("The `jwk` in the header is not a key {algorithm:?} signs with"));
    }

    let claims = verify(jwt, &DecodingKey::from_jwk(&jwk)?, algorithm)?;
    Ok((claims, jwk))
}

/// Refuses a JWT whose protected header has a `crit` member, whatever its value. RFC 7515, Section 4.1.11: a JWS with
/// a critical extension that is not understood is invalid, and these crates process none. `jsonwebtoken` reads `crit`
/// without acting on it, and reads `"crit": null` as no member at all, so the header is looked at as it was sent.
pub fn ensure_no_critical_extension(jwt: &str) -> Result<()> {
    if has_header_member(jwt, "crit") {
        return Err(anyhow!(
            "A JWT with a `crit` header is not accepted: no extension is supported."
        ));
    }
    Ok(())
}

/// Whether the protected header of `jwt` has a member `name`, whatever its value (`null` included).
fn has_header_member(jwt: &str, name: &str) -> bool {
    jwt.split('.')
        .next()
        .and_then(|header| URL_SAFE_NO_PAD.decode(header).ok())
        .and_then(|header| serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&header).ok())
        .is_some_and(|header| header.contains_key(name))
}

/// Whether `coordinate`, a base64url value of a JWK, is 32 bytes: an Ed25519 key or one coordinate of a P-256 key.
fn decodes_to_32_bytes(coordinate: &str) -> bool {
    URL_SAFE_NO_PAD.decode(coordinate).is_ok_and(|bytes| bytes.len() == 32)
}

fn verify<T>(jwt: &str, decoding_key: &DecodingKey, algorithm: Algorithm) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    Ok(jsonwebtoken::decode::<T>(jwt, decoding_key, &validation)?.claims)
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

    async fn jwt_naming_its_key_by_jwk(claims: Value) -> String {
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();
        encode_with_jwk(Arc::new(subject), Header::new(Algorithm::EdDSA), claims, "did:test")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn decode_with_jwk_verifies_with_the_key_in_the_header() {
        let claims = json!({ "aud": "https://issuer.example", "iat": 1593436422 });
        let encoded = jwt_naming_its_key_by_jwk(claims.clone()).await;

        let (decoded, jwk): (Value, Jwk) = decode_with_jwk(&encoded).unwrap();

        assert_eq!(decoded, claims);
        assert_eq!(jwk, jsonwebtoken::decode_header(&encoded).unwrap().jwk.unwrap());
    }

    #[tokio::test]
    async fn decode_with_jwk_refuses_a_critical_extension() {
        // Signed correctly, with an extension the sender marks as one that must be understood.
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();
        let header = Header {
            crit: Some(vec!["unsupported-extension".to_string()]),
            ..Header::new(Algorithm::EdDSA)
        };
        let encoded = encode_with_jwk(Arc::new(subject), header, json!({ "iat": 1593436422 }), "did:test")
            .await
            .unwrap();
        assert!(jsonwebtoken::decode_header(&encoded).unwrap().crit.is_some());

        let error = decode_with_jwk::<Value>(&encoded).unwrap_err().to_string();

        assert!(error.contains("`crit`"), "{error}");
    }

    #[tokio::test]
    async fn decode_with_jwk_refuses_a_crit_member_that_is_null() {
        // `jsonwebtoken` cannot write `"crit": null`, so the JWT is put together and signed by hand.
        let subject = TestSubject::new("did:test:123".to_string(), "key_id".to_string()).unwrap();
        let jwk = public_jwk(&subject.public_key("key_id").await.unwrap(), Algorithm::EdDSA).unwrap();
        let signed = |header: Value| {
            let subject = &subject;
            async move {
                let message = [
                    base64_url_encode(&header).unwrap(),
                    base64_url_encode(&json!({ "iat": 1593436422 })).unwrap(),
                ]
                .join(".");
                let signature = subject.sign(&message, "did:test", Algorithm::EdDSA).await.unwrap();
                [message, URL_SAFE_NO_PAD.encode(signature)].join(".")
            }
        };

        // The control: the same JWT without the member verifies.
        let without_crit = signed(json!({ "typ": "JWT", "alg": "EdDSA", "jwk": jwk })).await;
        assert!(decode_with_jwk::<Value>(&without_crit).is_ok());

        let with_null_crit = signed(json!({ "typ": "JWT", "alg": "EdDSA", "jwk": jwk, "crit": null })).await;
        assert_eq!(jsonwebtoken::decode_header(&with_null_crit).unwrap().crit, None);
        let error = decode_with_jwk::<Value>(&with_null_crit).unwrap_err().to_string();
        assert!(error.contains("`crit`"), "{error}");
    }

    #[test]
    fn decode_with_jwk_refuses_a_p256_key_with_coordinates_of_another_length() {
        // The point of RFC 7515, Appendix A.3.1, with one byte moved from `x` to `y`: the same 64 bytes when joined.
        let x = URL_SAFE_NO_PAD
            .decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
            .unwrap();
        let y = URL_SAFE_NO_PAD
            .decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
            .unwrap();
        let (short_x, long_y) = (&x[..31], [&x[31..], &y[..]].concat());
        let jwt_with = |x: &[u8], y: &[u8]| {
            let header = json!({
                "alg": "ES256",
                "jwk": { "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y) }
            });
            [
                base64_url_encode(&header).unwrap(),
                base64_url_encode(&json!({})).unwrap(),
                URL_SAFE_NO_PAD.encode([0u8; 64]),
            ]
            .join(".")
        };

        // The well-formed key gets as far as the signature, which is not one of this key.
        let error = decode_with_jwk::<Value>(&jwt_with(&x, &y)).unwrap_err().to_string();
        assert!(!error.contains("is not a key"), "{error}");

        let error = decode_with_jwk::<Value>(&jwt_with(short_x, &long_y))
            .unwrap_err()
            .to_string();
        assert!(error.contains("is not a key ES256 signs with"), "{error}");
    }

    #[tokio::test]
    async fn decode_with_jwk_refuses_a_jwt_that_another_key_signed() {
        let encoded = jwt_naming_its_key_by_jwk(json!({ "aud": "https://issuer.example" })).await;
        let (header, rest) = encoded.split_once('.').unwrap();

        // The same JWT, with another Ed25519 key in its header.
        let mut header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        header["jwk"]["x"] = json!(URL_SAFE_NO_PAD.encode([7u8; 32]));
        let forged = [base64_url_encode(&header).unwrap().as_str(), rest].join(".");

        assert!(decode_with_jwk::<Value>(&forged).is_err());
    }

    #[tokio::test]
    async fn decode_with_jwk_refuses_a_header_that_does_not_name_one_fitting_key() {
        let encoded = jwt_naming_its_key_by_jwk(json!({ "aud": "https://issuer.example" })).await;
        let (header, rest) = encoded.split_once('.').unwrap();
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        let with_header = |change: fn(&mut Value)| {
            let mut header = header.clone();
            change(&mut header);
            [base64_url_encode(&header).unwrap().as_str(), rest].join(".")
        };

        // "jwk: ... It MUST NOT be present if kid is present" (OpenID4VCI 1.0, Appendix F.1).
        let with_kid = with_header(|header| header["kid"] = json!("did:test:123#key_id"));
        assert!(decode_with_jwk::<Value>(&with_kid).is_err());

        let without_jwk = with_header(|header| {
            header.as_object_mut().unwrap().remove("jwk");
        });
        assert!(decode_with_jwk::<Value>(&without_jwk).is_err());

        // An Ed25519 key cannot have made an ES256 signature.
        let other_algorithm = with_header(|header| header["alg"] = json!("ES256"));
        assert!(decode_with_jwk::<Value>(&other_algorithm).is_err());

        // A key of an algorithm outside `JWK_ALGORITHMS`.
        let unsupported = with_header(|header| {
            header["alg"] = json!("HS256");
            header["jwk"] = json!({ "kty": "oct", "k": "c2VjcmV0" });
        });
        assert!(decode_with_jwk::<Value>(&unsupported).is_err());
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
