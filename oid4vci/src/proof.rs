use crate::credential_issuer::credential_configurations_supported::AlgIdentifier;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{builder_fn, jwt, RFC7519Claims, Subject};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Proof Type as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(tag = "proof_type")]
pub enum Proof {
    #[serde(rename = "jwt")]
    Jwt { jwt: String },
    // TODO: add support for other proof types
    // #[serde(rename = "di_vp")]
    // DiVp { di_vp: String },
    // #[serde(rename = "attestation")]
    // Attestation { attestation: String },
}

impl Proof {
    pub fn builder() -> ProofBuilder {
        ProofBuilder::default()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct KeyProofMetadata {
    pub proof_signing_alg_values_supported: Vec<AlgIdentifier>,
    // TODO: add `key_attestations_required`
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Jwt,
    // TODO: support other proof types
}

#[derive(Default)]
pub struct ProofBuilder {
    proof_type: Option<ProofType>,
    algorithm: Option<Algorithm>,
    rfc7519_claims: RFC7519Claims,
    nonce: Option<String>,
    signer: Option<Arc<dyn Subject>>,
    subject_syntax_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofOfPossession {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl ProofBuilder {
    pub async fn build(self) -> anyhow::Result<Proof> {
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");

        let subject_syntax_type = self
            .subject_syntax_type
            .ok_or(anyhow::anyhow!("subject_syntax_type is required"))?;

        tracing::debug!(
            proof_type = ?self.proof_type,
            algorithm = ?self.algorithm,
            subject_syntax_type = %subject_syntax_type,
            has_nonce = self.nonce.is_some(),
            "Building key possession proof for credential request"
        );

        match self.proof_type {
            Some(ProofType::Jwt) => Ok(Proof::Jwt {
                jwt: jwt::encode(
                    self.signer.ok_or(anyhow::anyhow!("No subject found"))?.clone(),
                    Header {
                        alg: self.algorithm.ok_or(anyhow::anyhow!("algorithm is required"))?,
                        typ: Some("openid4vci-proof+jwt".to_string()),
                        ..Default::default()
                    },
                    ProofOfPossession {
                        rfc7519_claims: self.rfc7519_claims,
                        nonce: self.nonce,
                    },
                    &subject_syntax_type,
                )
                .await?,
            }),
            None => Err(anyhow::anyhow!("proof_type is required")),
        }
    }

    pub fn signer(mut self, signer: Arc<dyn Subject>) -> Self {
        self.signer = Some(signer);
        self
    }

    builder_fn!(proof_type, ProofType);
    builder_fn!(algorithm, Algorithm);
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(nonce, String);
    builder_fn!(subject_syntax_type, String);
}
