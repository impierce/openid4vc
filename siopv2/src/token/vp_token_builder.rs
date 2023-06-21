// TODO: Move this to the OID4vp crate
use super::id_token::RFC7519Claims;
use crate::{builder_fn, token::vp_token::VpToken};
use anyhow::{anyhow, Result};
use identity_credential::presentation::JwtPresentation;

#[derive(Default)]
pub struct VpTokenBuilder {
    rfc7519_claims: RFC7519Claims,
    verifiable_presentation: Option<JwtPresentation>,
    // TODO: Is this required?
    nonce: Option<String>,
}

impl VpTokenBuilder {
    pub fn new() -> Self {
        VpTokenBuilder::default()
    }

    pub fn build(self) -> Result<VpToken> {
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

        Ok(VpToken {
            rfc7519_claims: self.rfc7519_claims,
            verifiable_presentation: self
                .verifiable_presentation
                .ok_or_else(|| anyhow!("verifiable_presentation is required"))?,
            nonce: self.nonce,
        })
    }

    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(verifiable_presentation, JwtPresentation);
    builder_fn!(nonce, String);
}
