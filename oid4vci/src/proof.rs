use crate::credential_issuer::credential_configurations_supported::AlgIdentifier;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{RFC7519Claims, Subject, builder_fn, jwt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Proof Type as described here: <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types>
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

/// Algorithms supported by the Credential Issuer for a key proof type.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct KeyProofMetadata {
    pub proof_signing_alg_values_supported: Vec<AlgIdentifier>,
    // TODO: add `key_attestations_required`
}

/// Key proof types supported by the Credential Issuer.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Jwt,
    // TODO: support other proof types
}

/// How a `jwt` key proof names the key it proves possession of: "kid", "jwk" and "x5c" are the three JOSE headers
/// of OpenID4VCI 1.0, Appendix F.1, of which a proof carries one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProofKeyReference {
    /// By reference, in `kid`: the signer's key identifier, such as a DID URL.
    #[default]
    Kid,
    /// By value, in `jwk`: the public key itself. For an issuer whose `cryptographic_binding_methods_supported`
    /// has `jwk`.
    Jwk,
}

#[derive(Default)]
pub struct ProofBuilder {
    proof_type: Option<ProofType>,
    algorithm: Option<Algorithm>,
    rfc7519_claims: RFC7519Claims,
    nonce: Option<String>,
    signer: Option<Arc<dyn Subject>>,
    subject_syntax_type: Option<String>,
    key_reference: ProofKeyReference,
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
            Some(ProofType::Jwt) => {
                let signer = self.signer.ok_or(anyhow::anyhow!("No subject found"))?;
                let header = Header {
                    alg: self.algorithm.ok_or(anyhow::anyhow!("algorithm is required"))?,
                    typ: Some("openid4vci-proof+jwt".to_string()),
                    ..Default::default()
                };
                let claims = ProofOfPossession {
                    rfc7519_claims: self.rfc7519_claims,
                    nonce: self.nonce,
                };
                let jwt = match self.key_reference {
                    ProofKeyReference::Kid => jwt::encode(signer, header, claims, &subject_syntax_type).await?,
                    ProofKeyReference::Jwk => {
                        jwt::encode_with_jwk(signer, header, claims, &subject_syntax_type).await?
                    }
                };
                Ok(Proof::Jwt { jwt })
            }
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

    /// How the proof names its key: [`ProofKeyReference::Kid`] unless set.
    pub fn key_reference(mut self, key_reference: ProofKeyReference) -> Self {
        self.key_reference = key_reference;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oid4vc_core::{test_utils::TestSubject, utils::jwt::get_unverified_jwt_claims};
    use serde_json::{Value, json};

    async fn proof(key_reference: ProofKeyReference) -> (Value, Value) {
        let subject = TestSubject::new("did:test:123".to_string(), "did:test:123#key-1".to_string()).unwrap();
        let Proof::Jwt { jwt } = Proof::builder()
            .proof_type(ProofType::Jwt)
            .algorithm(Algorithm::EdDSA)
            .signer(Arc::new(subject))
            .subject_syntax_type("did:test")
            .key_reference(key_reference)
            .aud("https://credential-issuer.example.com")
            .iat(1_701_960_444)
            .nonce("LarRGSbmUPYtRYO6BQ4yn8")
            .build()
            .await
            .unwrap();
        let header = serde_json::to_value(jsonwebtoken::decode_header(&jwt).unwrap()).unwrap();
        (header, get_unverified_jwt_claims(&json!(jwt)).unwrap())
    }

    #[tokio::test]
    async fn a_key_proof_names_its_key_by_kid_unless_asked_otherwise() {
        let (header, claims) = proof(ProofKeyReference::default()).await;

        assert_eq!(
            header,
            json!({ "typ": "openid4vci-proof+jwt", "alg": "EdDSA", "kid": "did:test:123#key-1" })
        );
        assert_eq!(
            claims,
            json!({
                "aud": "https://credential-issuer.example.com",
                "iat": 1_701_960_444,
                "nonce": "LarRGSbmUPYtRYO6BQ4yn8"
            })
        );
    }

    /// The shape of the example in OpenID4VCI 1.0, Appendix F.1: `typ`, `alg` and `jwk`, and no `kid`.
    #[tokio::test]
    async fn a_key_proof_can_name_its_key_by_jwk() {
        let (header, claims) = proof(ProofKeyReference::Jwk).await;

        assert_eq!(header["typ"], "openid4vci-proof+jwt");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header.get("kid"), None);
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");
        assert!(header["jwk"]["x"].is_string());
        // No private part, and nothing but the key.
        assert_eq!(header["jwk"].as_object().unwrap().len(), 3);
        assert_eq!(claims["aud"], "https://credential-issuer.example.com");
    }
}
