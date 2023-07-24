use crate::serialize_unit_struct;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{builder_fn, jwt, RFC7519Claims, Subject};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub struct Jwt;

#[derive(Debug, PartialEq, Eq)]
pub struct Cwt;

serialize_unit_struct!("jwt", Jwt);
serialize_unit_struct!("cwt", Cwt);

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Proof {
    Jwt { proof_type: Jwt, jwt: String },
    Cwt { proof_type: Cwt, cwt: String },
}

impl Proof {
    pub fn builder() -> ProofBuilder {
        ProofBuilder::default()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Jwt,
    Cwt,
}

#[derive(Default)]
pub struct ProofBuilder {
    proof_type: Option<ProofType>,
    rfc7519_claims: RFC7519Claims,
    nonce: Option<String>,
    signer: Option<Arc<dyn Subject>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOfPossession {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub nonce: String,
}

impl ProofBuilder {
    pub fn build(self) -> anyhow::Result<Proof> {
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        anyhow::ensure!(self.nonce.is_some(), "nonce claim is required");

        match self.proof_type {
            Some(ProofType::Jwt) => Ok(Proof::Jwt {
                proof_type: Jwt,
                jwt: jwt::encode(
                    self.signer.ok_or(anyhow::anyhow!("No subject found"))?.clone(),
                    Header {
                        alg: Algorithm::EdDSA,
                        typ: Some("openid4vci-proof+jwt".to_string()),
                        ..Default::default()
                    },
                    ProofOfPossession {
                        rfc7519_claims: self.rfc7519_claims,
                        nonce: self.nonce.ok_or(anyhow::anyhow!("No nonce found"))?,
                    },
                )?,
            }),
            Some(ProofType::Cwt) => todo!(),
            None => Err(anyhow::anyhow!("proof_type is required")),
        }
    }

    pub fn signer(mut self, signer: Arc<dyn Subject>) -> Self {
        self.signer = Some(signer);
        self
    }

    builder_fn!(proof_type, ProofType);
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, aud, String);
    // TODO: fix this, required by jsonwebtoken crate.
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(nonce, String);
}
