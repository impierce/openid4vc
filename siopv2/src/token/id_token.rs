use super::id_token_builder::IdTokenBuilder;
use crate::{parse_other, StandardClaimsValues};
use oid4vc_core::{JsonObject, RFC7519Claims};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// An SIOPv2 [`IdToken`] as specified in the [SIOPv2 specification](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-id-token)
/// and [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct IdToken {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    #[serde(flatten)]
    pub standard_claims: StandardClaimsValues,
    pub auth_time: Option<i64>,
    pub nonce: Option<String>,
    pub acr: Option<String>,
    pub amr: Option<Vec<String>>,
    pub azp: Option<String>,
    pub sub_jwk: Option<SubJwk>,
    #[serde(flatten, deserialize_with = "parse_other")]
    pub other: Option<JsonObject>,
}

impl IdToken {
    pub fn builder() -> IdTokenBuilder {
        IdTokenBuilder::new()
    }
}

// TODO: Make feature complete.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct SubJwk {
    pub kty: String,
    pub n: String,
    pub e: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_token() {
        let id_token: IdToken = serde_json::from_str(
            r#"{
                "iss": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
                "sub": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
                "aud": "https://client.example.org/cb",
                "nonce": "n-0S6_WzA2Mj",
                "exp": 1311281970,
                "iat": 1311280970,
                "sub_jwk": {
                  "kty": "RSA",
                  "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                  "e": "AQAB"
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            id_token,
            IdToken {
                rfc7519_claims: RFC7519Claims {
                    iss: Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".to_string()),
                    sub: Some("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".to_string()),
                    aud: Some("https://client.example.org/cb".to_string()),
                    exp: Some(1311281970),
                    iat: Some(1311280970),
                    ..Default::default()
                },
                nonce: Some("n-0S6_WzA2Mj".to_string()),
                sub_jwk: Some(SubJwk {
                    kty: "RSA".to_string(),
                    n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string(),
                    e: "AQAB".to_string(),
                }),
                ..Default::default()
            }
        );
    }
}
