use identity_ecdsa_verifier::EcDSAJwsVerifier;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_verification::{
    jwk::Jwk,
    jws::{JwsAlgorithm, JwsVerifier, SignatureVerificationError, SignatureVerificationErrorKind, VerificationInput},
};

/// A simple JWS verifier that supports EdDSA and ES256/ES256K algorithms. This can be used to verify signatures on JWTs and other JWS objects.
#[derive(Clone)]
pub struct SignatureVerifier;

impl JwsVerifier for SignatureVerifier {
    fn verify(&self, input: VerificationInput, public_key: &Jwk) -> Result<(), SignatureVerificationError> {
        use JwsAlgorithm::*;

        match input.alg {
            EdDSA => EdDSAJwsVerifier::default().verify(input, public_key),
            ES256 | ES256K => EcDSAJwsVerifier::default().verify(input, public_key),
            // TODO: Add support for more algorithms.
            _ => Err(SignatureVerificationErrorKind::UnsupportedAlg.into()),
        }
    }
}
