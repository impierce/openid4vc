pub mod authorization_server_metadata;
pub mod credential_configurations_supported;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{proof::ProofOfPossession, proofs::Proofs};
use jsonwebtoken::jwk::Jwk;
use oid4vc_core::{Validator, authentication::subject::SigningSubject, jwt};

#[derive(Clone)]
pub struct CredentialIssuer {
    pub subject: SigningSubject,
    pub metadata: CredentialIssuerMetadata,
    pub authorization_server_metadata: AuthorizationServerMetadata,
}

/// The key a key proof proves possession of: what the credential is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofKey {
    /// Named by the proof's `kid` header: a key identifier, such as a DID URL.
    Kid(String),
    /// Carried in the proof's `jwk` header.
    Jwk(Box<Jwk>),
}

/// A key proof that validated: its claims and the key it was verified with.
#[derive(Debug)]
pub struct ValidatedProof {
    pub proof_of_possession: ProofOfPossession,
    pub key: ProofKey,
}

impl CredentialIssuer {
    /// Validates key proofs that name their key by `kid`: each is verified with the key `validator` finds for its
    /// `kid`. A proof without a `kid` is refused. For proofs that name their key by `jwk`, see
    /// [`CredentialIssuer::validate_proofs_for_configuration`].
    pub async fn validate_proofs(
        &self,
        proofs: Proofs,
        validator: Validator,
    ) -> anyhow::Result<Vec<ProofOfPossession>> {
        if proofs.jwt.is_empty() {
            return Err(anyhow::anyhow!("No JWTs found in proofs"));
        }

        let mut validated_proofs = Vec::new();
        for jwt in &proofs.jwt {
            let proof_of_possession = validator.decode(jwt.clone()).await?;
            validated_proofs.push(proof_of_possession);
        }

        Ok(validated_proofs)
    }

    /// Validates the key proofs of a Credential Request for the Credential Configuration it asks for, and returns
    /// each with the key it was verified with.
    ///
    /// - A proof that names its key by `kid` is verified with the key `validator` finds for it, as in
    ///   [`CredentialIssuer::validate_proofs`].
    /// - A proof that names its key by value (a `jwk` header and no `kid`) is verified with that key, and only when
    ///   `cryptographic_binding_methods_supported` of this Credential Configuration has `jwk`. For any other
    ///   configuration it is refused, also when another configuration of this Credential Issuer binds to `jwk`.
    ///
    /// The signature of a `jwk` proof shows possession of the key and nothing about who holds it: bind the credential
    /// to the returned [`ProofKey`], not to a claim of the proof.
    pub async fn validate_proofs_for_configuration(
        &self,
        proofs: Proofs,
        validator: Validator,
        credential_configuration_id: &str,
    ) -> anyhow::Result<Vec<ValidatedProof>> {
        if proofs.jwt.is_empty() {
            return Err(anyhow::anyhow!("No JWTs found in proofs"));
        }

        let binds_to_a_jwk = self
            .metadata
            .credential_configurations_supported
            .get(credential_configuration_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown Credential Configuration `{credential_configuration_id}`"))?
            .cryptographic_binding_methods_supported
            .iter()
            .any(|binding_method| binding_method == "jwk");

        let mut validated_proofs = Vec::new();
        for jwt in &proofs.jwt {
            let validated_proof = if names_its_key_by_jwk(jwt) {
                anyhow::ensure!(
                    binds_to_a_jwk,
                    "The Credential Configuration `{credential_configuration_id}` does not bind to a JWK: a key proof \
                     has to name its key by `kid`"
                );
                let (proof_of_possession, jwk) = jwt::decode_with_jwk(jwt)?;
                ValidatedProof {
                    proof_of_possession,
                    key: ProofKey::Jwk(Box::new(jwk)),
                }
            } else {
                let (kid, _) = jwt::extract_header(jwt)?;
                ValidatedProof {
                    proof_of_possession: validator.decode(jwt.clone()).await?,
                    key: ProofKey::Kid(kid),
                }
            };
            validated_proofs.push(validated_proof);
        }

        Ok(validated_proofs)
    }
}

/// "jwk: ... It MUST NOT be present if kid is present" (OpenID4VCI 1.0, Appendix F.1): a proof with both is left to
/// its `kid`.
fn names_its_key_by_jwk(jwt: &str) -> bool {
    jsonwebtoken::decode_header(jwt).is_ok_and(|header| header.kid.is_none() && header.jwk.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject,
        proof::{Proof, ProofKeyReference, ProofType},
    };
    use jsonwebtoken::Algorithm;
    use oid4vc_core::test_utils::{MockVerifier, TestSubject};
    use std::sync::Arc;

    /// A Credential Issuer with one Credential Configuration per entry: its identifier and what it binds to.
    fn credential_issuer_binding(configurations: &[(&str, &[&str])]) -> CredentialIssuer {
        CredentialIssuer {
            subject: Arc::new(TestSubject::default()),
            metadata: CredentialIssuerMetadata {
                credential_configurations_supported: configurations
                    .iter()
                    .map(|(id, binding_methods)| {
                        let credential_configuration = CredentialConfigurationsSupportedObject {
                            cryptographic_binding_methods_supported: binding_methods
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                            ..Default::default()
                        };
                        (id.to_string(), credential_configuration)
                    })
                    .collect(),
                ..Default::default()
            },
            authorization_server_metadata: AuthorizationServerMetadata::default(),
        }
    }

    /// An issuer that binds one credential to a JWK and another to identifiers only.
    fn mixed_credential_issuer() -> CredentialIssuer {
        credential_issuer_binding(&[("BoundToJwk", &["jwk"]), ("BoundToDid", &["did:test"])])
    }

    async fn proofs(key_reference: ProofKeyReference) -> Proofs {
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
        Proofs { jwt: vec![jwt] }
    }

    fn validator() -> Validator {
        Validator::Verifier(Arc::new(MockVerifier::new()))
    }

    #[tokio::test]
    async fn a_jwk_proof_is_valid_for_a_configuration_binding_to_jwk_and_gives_its_key() {
        let proofs = proofs(ProofKeyReference::Jwk).await;
        let key_in_the_header = jsonwebtoken::decode_header(&proofs.jwt[0]).unwrap().jwk.unwrap();

        let validated = mixed_credential_issuer()
            .validate_proofs_for_configuration(proofs, validator(), "BoundToJwk")
            .await
            .unwrap();

        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].key, ProofKey::Jwk(Box::new(key_in_the_header)));
        assert_eq!(
            validated[0].proof_of_possession.nonce.as_deref(),
            Some("LarRGSbmUPYtRYO6BQ4yn8")
        );
    }

    #[tokio::test]
    async fn a_jwk_proof_is_refused_for_a_configuration_binding_to_identifiers_only() {
        // Also when another configuration of the same issuer binds to a JWK.
        let error = mixed_credential_issuer()
            .validate_proofs_for_configuration(proofs(ProofKeyReference::Jwk).await, validator(), "BoundToDid")
            .await
            .unwrap_err();

        assert!(error.to_string().contains("does not bind to a JWK"), "{error}");
    }

    #[tokio::test]
    async fn a_kid_proof_is_valid_for_either_configuration_and_gives_its_key_identifier() {
        for credential_configuration_id in ["BoundToJwk", "BoundToDid"] {
            let validated = mixed_credential_issuer()
                .validate_proofs_for_configuration(
                    proofs(ProofKeyReference::Kid).await,
                    validator(),
                    credential_configuration_id,
                )
                .await
                .unwrap();

            assert_eq!(validated.len(), 1);
            assert_eq!(validated[0].key, ProofKey::Kid("did:test:123#key-1".to_string()));
        }
    }

    #[tokio::test]
    async fn proofs_for_an_unknown_configuration_are_refused() {
        let error = mixed_credential_issuer()
            .validate_proofs_for_configuration(proofs(ProofKeyReference::Kid).await, validator(), "Unknown")
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "Unknown Credential Configuration `Unknown`");
    }

    /// `validate_proofs` is for `kid` proofs, whatever the issuer binds to.
    #[tokio::test]
    async fn validate_proofs_takes_kid_proofs_only() {
        let credential_issuer = mixed_credential_issuer();

        let validated = credential_issuer
            .validate_proofs(proofs(ProofKeyReference::Kid).await, validator())
            .await
            .unwrap();
        assert_eq!(validated.len(), 1);

        let error = credential_issuer
            .validate_proofs(proofs(ProofKeyReference::Jwk).await, validator())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "No key identifier found in the header.");
    }
}
