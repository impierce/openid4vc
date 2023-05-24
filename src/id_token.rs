use crate::{builder_fn, StandardClaimsValues};
use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// TODO: make fully feature complete and implement builder pattern: https://github.com/impierce/siopv2/issues/20
/// An SIOPv2 [`IdToken`] as specified in the [SIOPv2 specification](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-id-token).
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Getters, Default, PartialEq)]
pub struct IdToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    rfc7519_claims: RFC7519Claims,
    #[serde(flatten)]
    #[getset(get = "pub")]
    standard_claims: StandardClaimsValues,
    nonce: Option<String>,
    state: Option<String>,
    sub_jwk: Option<String>,
}

impl IdToken {
    pub fn builder() -> IdTokenBuilder {
        IdTokenBuilder::new()
    }
}

/// Set of IANA registered claims by the Internet Engineering Task Force (IETF) in
/// [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1).
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct RFC7519Claims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
}

#[derive(Default)]
pub struct IdTokenBuilder {
    rfc7519_claims: RFC7519Claims,
    standard_claims: StandardClaimsValues,
    nonce: Option<String>,
    state: Option<String>,
    sub_jwk: Option<String>,
}

impl IdTokenBuilder {
    pub fn new() -> Self {
        IdTokenBuilder::default()
    }

    pub fn build(self) -> anyhow::Result<IdToken> {
        anyhow::ensure!(self.rfc7519_claims.iss.is_some(), "iss claim is required");
        anyhow::ensure!(self.rfc7519_claims.sub.is_some(), "sub claim is required");
        anyhow::ensure!(
            self.rfc7519_claims.sub.as_ref().filter(|s| s.len() <= 255).is_some(),
            "sub claim MUST NOT exceed 255 ASCII characters in length"
        );
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.exp.is_some(), "exp claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        anyhow::ensure!(
            self.rfc7519_claims.iss == self.rfc7519_claims.sub,
            "iss and sub must be equal"
        );

        Ok(IdToken {
            rfc7519_claims: self.rfc7519_claims,
            standard_claims: self.standard_claims,
            nonce: self.nonce,
            state: self.state,
            sub_jwk: self.sub_jwk,
        })
    }

    pub fn claims(mut self, claims: StandardClaimsValues) -> Self {
        self.standard_claims = claims;
        self
    }

    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(nonce, String);
    builder_fn!(state, String);
    builder_fn!(sub_jwk, String);
}
