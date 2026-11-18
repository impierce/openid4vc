pub mod authorization_server_metadata;
pub mod credential_configurations_supported;
pub mod credential_issuer_metadata;

use self::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::{
    credential_issuer::credential_configurations_supported::AlgIdentifier,
    proof::{ProofOfPossession, ProofType},
    proofs::Proofs,
};
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
    /// Either kind has to be a key proof as OpenID4VCI 1.0, Appendix F.1 defines it: its `typ` is
    /// `openid4vci-proof+jwt`, it has an `iat`, and it is signed with one of the algorithms the Credential
    /// Configuration lists for `jwt` proofs, when it lists any. The `nonce` and the `aud` are not checked here.
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

        let credential_configuration = self
            .metadata
            .credential_configurations_supported
            .get(credential_configuration_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown Credential Configuration `{credential_configuration_id}`"))?;
        let binds_to_a_jwk = credential_configuration
            .cryptographic_binding_methods_supported
            .iter()
            .any(|binding_method| binding_method == "jwk");
        // The algorithms listed for `jwt` proofs; a configuration that lists none takes what can be verified.
        let proof_algorithms = credential_configuration
            .proof_types_supported
            .get(&ProofType::Jwt)
            .map(|key_proof_metadata| &key_proof_metadata.proof_signing_alg_values_supported);

        let mut validated_proofs = Vec::new();
        for jwt in &proofs.jwt {
            let header = jsonwebtoken::decode_header(jwt)?;
            ensure_key_proof_typ(header.typ.as_deref())?;
            if let Some(proof_algorithms) = proof_algorithms {
                // `Algorithm` has no `Display`: its `Debug` form is the JWS name.
                let algorithm = format!("{:?}", header.alg);
                anyhow::ensure!(
                    proof_algorithms.contains(&AlgIdentifier::String(algorithm.clone())),
                    "The Credential Configuration `{credential_configuration_id}` takes no key proof signed with \
                     {algorithm}"
                );
            }

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
            anyhow::ensure!(
                validated_proof.proof_of_possession.rfc7519_claims.iat.is_some(),
                "A key proof has to have an `iat`"
            );
            validated_proofs.push(validated_proof);
        }

        Ok(validated_proofs)
    }
}

/// "typ: REQUIRED. MUST be openid4vci-proof+jwt" (OpenID4VCI 1.0, Appendix F.1). Compared as a media type (RFC 7515,
/// Section 4.1.9): case-insensitively, `application/` optional.
fn ensure_key_proof_typ(typ: Option<&str>) -> anyhow::Result<()> {
    let lowercase = typ.map(str::to_ascii_lowercase);
    let media_type = lowercase
        .as_deref()
        .map(|typ| typ.strip_prefix("application/").unwrap_or(typ));
    anyhow::ensure!(
        media_type == Some("openid4vci-proof+jwt"),
        "The typ of a key proof is {typ:?}, not \"openid4vci-proof+jwt\""
    );
    Ok(())
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

    /// A JWT that names its key by `jwk`, with this `typ` and these claims, signed as a proof is.
    async fn jwk_jwt(typ: &str, claims: serde_json::Value) -> Proofs {
        let subject = TestSubject::new("did:test:123".to_string(), "did:test:123#key-1".to_string()).unwrap();
        let header = jsonwebtoken::Header {
            typ: Some(typ.to_string()),
            ..jsonwebtoken::Header::new(Algorithm::EdDSA)
        };
        let jwt = jwt::encode_with_jwk(Arc::new(subject), header, claims, "did:test")
            .await
            .unwrap();
        Proofs { jwt: vec![jwt] }
    }

    #[tokio::test]
    async fn a_proof_has_to_have_the_typ_of_a_key_proof() {
        let claims = serde_json::json!({ "aud": "https://credential-issuer.example.com", "iat": 1_701_960_444 });
        let credential_issuer = mixed_credential_issuer();

        for typ in ["openid4vci-proof+jwt", "application/openid4vci-proof+jwt"] {
            let validated = credential_issuer
                .validate_proofs_for_configuration(jwk_jwt(typ, claims.clone()).await, validator(), "BoundToJwk")
                .await;
            assert!(validated.is_ok(), "{typ}");
        }

        let error = credential_issuer
            .validate_proofs_for_configuration(jwk_jwt("JWT", claims).await, validator(), "BoundToJwk")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not \"openid4vci-proof+jwt\""), "{error}");
    }

    #[tokio::test]
    async fn a_proof_has_to_have_an_iat() {
        let claims = serde_json::json!({ "aud": "https://credential-issuer.example.com" });

        let error = mixed_credential_issuer()
            .validate_proofs_for_configuration(jwk_jwt("openid4vci-proof+jwt", claims).await, validator(), "BoundToJwk")
            .await
            .unwrap_err();

        assert_eq!(error.to_string(), "A key proof has to have an `iat`");
    }

    /// The test signer signs with EdDSA only, so the algorithm that is taken is EdDSA.
    #[tokio::test]
    async fn a_proof_has_to_be_signed_with_an_algorithm_the_configuration_lists() {
        let taking = |algorithm: &str| {
            let mut credential_issuer = mixed_credential_issuer();
            for credential_configuration in credential_issuer
                .metadata
                .credential_configurations_supported
                .values_mut()
            {
                credential_configuration.proof_types_supported = [(
                    ProofType::Jwt,
                    crate::proof::KeyProofMetadata {
                        proof_signing_alg_values_supported: vec![AlgIdentifier::String(algorithm.to_string())],
                    },
                )]
                .into_iter()
                .collect();
            }
            credential_issuer
        };

        for (key_reference, credential_configuration_id) in [
            (ProofKeyReference::Jwk, "BoundToJwk"),
            (ProofKeyReference::Kid, "BoundToDid"),
        ] {
            let validated = taking("EdDSA")
                .validate_proofs_for_configuration(
                    proofs(key_reference).await,
                    validator(),
                    credential_configuration_id,
                )
                .await;
            assert!(validated.is_ok(), "{key_reference:?}");

            let error = taking("ES256")
                .validate_proofs_for_configuration(
                    proofs(key_reference).await,
                    validator(),
                    credential_configuration_id,
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("takes no key proof signed with EdDSA"),
                "{key_reference:?}: {error}"
            );
        }
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
