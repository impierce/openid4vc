pub mod authorization_server_metadata;
pub mod credential_configurations_supported;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{proof::ProofOfPossession, proofs::Proofs};
use oid4vc_core::{Validator, authentication::subject::SigningSubject, jwt};

#[derive(Clone)]
pub struct CredentialIssuer {
    pub subject: SigningSubject,
    pub metadata: CredentialIssuerMetadata,
    pub authorization_server_metadata: AuthorizationServerMetadata,
}

impl CredentialIssuer {
    /// Validates the key proofs of a Credential Request.
    ///
    /// A proof that names its key by `kid` is verified with the key `validator` finds for it. A proof that names its
    /// key by value (a `jwk` header and no `kid`) is verified with that key, and only when this Credential Issuer binds
    /// credentials to a JWK: when `cryptographic_binding_methods_supported` of one of its Credential Configurations has
    /// `jwk`. The key of such a proof is the `jwk` in its header, which [`jwt::decode_with_jwk`] returns.
    pub async fn validate_proofs(
        &self,
        proofs: Proofs,
        validator: Validator,
    ) -> anyhow::Result<Vec<ProofOfPossession>> {
        if proofs.jwt.is_empty() {
            return Err(anyhow::anyhow!("No JWTs found in proofs"));
        }

        let binds_credentials_to_a_jwk = self.binds_credentials_to_a_jwk();

        let mut validated_proofs = Vec::new();
        for jwt in &proofs.jwt {
            let proof_of_possession = if binds_credentials_to_a_jwk && names_its_key_by_jwk(jwt) {
                jwt::decode_with_jwk(jwt)?.0
            } else {
                validator.decode(jwt.clone()).await?
            };
            validated_proofs.push(proof_of_possession);
        }

        Ok(validated_proofs)
    }

    fn binds_credentials_to_a_jwk(&self) -> bool {
        self.metadata
            .credential_configurations_supported
            .values()
            .flat_map(|credential_configuration| &credential_configuration.cryptographic_binding_methods_supported)
            .any(|binding_method| binding_method == "jwk")
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

    fn credential_issuer_binding_to(binding_methods: &[&str]) -> CredentialIssuer {
        let credential_configuration = CredentialConfigurationsSupportedObject {
            cryptographic_binding_methods_supported: binding_methods.iter().map(ToString::to_string).collect(),
            ..Default::default()
        };
        CredentialIssuer {
            subject: Arc::new(TestSubject::default()),
            metadata: CredentialIssuerMetadata {
                credential_configurations_supported: [("ExampleCredential".to_string(), credential_configuration)]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
            authorization_server_metadata: AuthorizationServerMetadata::default(),
        }
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
    async fn a_proof_naming_its_key_by_jwk_is_valid_for_an_issuer_binding_to_jwk() {
        let credential_issuer = credential_issuer_binding_to(&["jwk"]);

        let validated = credential_issuer
            .validate_proofs(proofs(ProofKeyReference::Jwk).await, validator())
            .await
            .unwrap();

        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].nonce.as_deref(), Some("LarRGSbmUPYtRYO6BQ4yn8"));
    }

    #[tokio::test]
    async fn a_proof_naming_its_key_by_jwk_is_refused_by_an_issuer_binding_to_identifiers_only() {
        let credential_issuer = credential_issuer_binding_to(&["did:test"]);

        let error = credential_issuer
            .validate_proofs(proofs(ProofKeyReference::Jwk).await, validator())
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "No key identifier found in the header.");
    }

    #[tokio::test]
    async fn a_proof_naming_its_key_by_kid_is_valid_whatever_the_issuer_binds_to() {
        for binding_methods in [&["jwk"][..], &["did:test"], &["jwk", "did:test"]] {
            let validated = credential_issuer_binding_to(binding_methods)
                .validate_proofs(proofs(ProofKeyReference::Kid).await, validator())
                .await
                .unwrap();

            assert_eq!(validated.len(), 1);
        }
    }
}
