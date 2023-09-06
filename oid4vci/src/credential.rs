use anyhow::{anyhow, Result};
use getset::Getters;
use oid4vc_core::{builder_fn, JsonValue, RFC7519Claims};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Getters)]
pub struct VerifiableCredentialJwt {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    #[serde(rename = "vc")]
    #[getset(get = "pub")]
    pub verifiable_credential: JsonValue,
}

impl VerifiableCredentialJwt {
    pub fn builder() -> VerifiableCredentialJwtBuilder {
        VerifiableCredentialJwtBuilder::new()
    }
}

#[derive(Default)]
pub struct VerifiableCredentialJwtBuilder {
    rfc7519_claims: RFC7519Claims,
    verifiable_credential: Option<JsonValue>,
}

impl VerifiableCredentialJwtBuilder {
    pub fn new() -> Self {
        VerifiableCredentialJwtBuilder::default()
    }

    pub fn build(self) -> Result<VerifiableCredentialJwt> {
        Ok(VerifiableCredentialJwt {
            rfc7519_claims: self.rfc7519_claims,
            verifiable_credential: self
                .verifiable_credential
                .ok_or_else(|| anyhow!("verifiable_credential is required"))?,
        })
    }

    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(verifiable_credential, JsonValue);
}
