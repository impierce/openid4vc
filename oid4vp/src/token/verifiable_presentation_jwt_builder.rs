use super::verifiable_presentation_jwt::{VerifiablePresentation, VerifiablePresentationJwt};
use anyhow::{Result, anyhow};
use oid4vc_core::{RFC7519Claims, builder_fn};

#[derive(Default)]
pub struct VerifiablePresentationJwtBuilder {
    rfc7519_claims: RFC7519Claims,
    verifiable_presentation: Option<VerifiablePresentation>,
    nonce: Option<String>,
}

impl VerifiablePresentationJwtBuilder {
    pub fn new() -> Self {
        VerifiablePresentationJwtBuilder::default()
    }

    pub fn build(self) -> Result<VerifiablePresentationJwt> {
        anyhow::ensure!(self.rfc7519_claims.iss.is_some(), "iss claim is required");
        anyhow::ensure!(self.rfc7519_claims.sub.is_some(), "sub claim is required");
        // TODO: According to https://openid.net/specs/openid-connect-core-1_0.html#IDToken, the sub claim MUST NOT
        // exceed 255 ASCII characters in length. However, for `did:jwk` it can be longer so we need to figure out how
        // to deal with this.
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

        let verifiable_presentation = self
            .verifiable_presentation
            .ok_or_else(|| anyhow!("verifiable_presentation is required"))?;
        // The holder signs the presentation, so `iss` is the holder (VCDM 1.1 §6.3.1, VC-JOSE-COSE §3.2).
        if let Some(holder) = verifiable_presentation.holder() {
            anyhow::ensure!(
                self.rfc7519_claims.iss.as_deref() == Some(holder.id().as_str()),
                "the holder of the presentation must be the iss claim"
            );
        }

        Ok(VerifiablePresentationJwt {
            rfc7519_claims: self.rfc7519_claims,
            verifiable_presentation,
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
    builder_fn!(verifiable_presentation, VerifiablePresentation);
    builder_fn!(nonce, String);
}
