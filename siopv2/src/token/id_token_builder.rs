use super::id_token::SubJwk;
use crate::{IdToken, StandardClaimsValues};
use oid4vc_core::{builder_fn, JsonObject, RFC7519Claims};

#[derive(Default)]
pub struct IdTokenBuilder {
    rfc7519_claims: RFC7519Claims,
    standard_claims: StandardClaimsValues,
    auth_time: Option<i64>,
    nonce: Option<String>,
    acr: Option<String>,
    amr: Option<Vec<String>>,
    azp: Option<String>,
    sub_jwk: Option<SubJwk>,
    other: Option<JsonObject>,
}

impl IdTokenBuilder {
    pub fn new() -> Self {
        IdTokenBuilder::default()
    }

    pub fn build(self) -> anyhow::Result<IdToken> {
        anyhow::ensure!(self.rfc7519_claims.iss.is_some(), "iss claim is required");
        anyhow::ensure!(self.rfc7519_claims.sub.is_some(), "sub claim is required");
        // TODO: According to https://openid.net/specs/openid-connect-core-1_0.html#IDToken, the sub claim MUST NOT
        // exceed 255 ASCII characters in length. However, for `did:jwk` it can be longer.
        // anyhow::ensure!(
        //     self.rfc7519_claims.sub.as_ref().filter(|s| s.len() <= 255).is_some(),
        //     "sub claim MUST NOT exceed 255 ASCII characters in length"
        // );
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
            auth_time: self.auth_time,
            nonce: self.nonce,
            acr: self.acr,
            amr: self.amr,
            azp: self.azp,
            sub_jwk: self.sub_jwk,
            other: self.other,
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
    builder_fn!(auth_time, i64);
    builder_fn!(nonce, String);
    builder_fn!(acr, String);
    builder_fn!(amr, Vec<String>);
    builder_fn!(azp, String);
    builder_fn!(sub_jwk, SubJwk);
    builder_fn!(other, JsonObject);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_build() {
        assert!(IdTokenBuilder::new()
            .iss("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
            .sub("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
            .aud("https://client.example.org/cb")
            .exp(1311281970)
            .iat(1311280970)
            .build()
            .is_ok());
    }

    #[test]
    fn test_invalid_build() {
        assert!(IdTokenBuilder::new().build().is_err());

        assert!(IdTokenBuilder::new()
            .iss("iss")
            .build()
            .unwrap_err()
            .to_string()
            .contains("sub claim is required"));

        // TODO: According to https://openid.net/specs/openid-connect-core-1_0.html#IDToken, the sub claim MUST NOT
        // exceed 255 ASCII characters in length. However, for `did:jwk` it can be longer.
        // assert!(IdTokenBuilder::new()
        //     .iss("iss")
        //     .sub("x".repeat(256))
        //     .build()
        //     .unwrap_err()
        //     .to_string()
        //     .contains("sub claim MUST NOT exceed 255 ASCII characters in length"));

        assert!(IdTokenBuilder::new()
            .iss("iss")
            .sub("sub")
            .aud("aud")
            .exp(0)
            .iat(0)
            .build()
            .unwrap_err()
            .to_string()
            .contains("iss and sub must be equal"));
    }
}
