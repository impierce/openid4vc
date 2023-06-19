use anyhow::{anyhow, Result};
use async_trait::async_trait;
use did_key::{generate, resolve, Config, CoreSign, DIDCore, Document, Ed25519KeyPair, KeyMaterial, PatchedKeyPair};
use siopv2::{Sign, Subject, Verify};

/// This [`KeySubject`] implements the [`Subject`] trait and can be used as a subject for a [`Provider`]. It uses the
/// 'key' DID method.
pub struct KeySubject {
    keypair: PatchedKeyPair,
    document: Document,
}

impl KeySubject {
    /// Creates a new [`KeySubject`].
    pub fn new() -> Self {
        let keypair = generate::<Ed25519KeyPair>(None);
        let document = keypair.get_did_document(Config::default());
        KeySubject { keypair, document }
    }

    /// Creates a new [`KeySubject`] from a [`PatchedKeyPair`].
    pub fn from_keypair(keypair: PatchedKeyPair) -> Self {
        let document = keypair.get_did_document(Config::default());
        KeySubject { keypair, document }
    }
}

impl Default for KeySubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Sign for KeySubject {
    fn key_id(&self) -> Option<String> {
        self.document
            .authentication
            .as_ref()
            .and_then(|authentication_methods| authentication_methods.get(0).cloned())
    }

    async fn sign(&self, message: &str) -> Result<Vec<u8>> {
        Ok(self.keypair.sign(message.as_bytes()).to_vec())
    }
}

#[async_trait]
impl Verify for KeySubject {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        Ok(resolve_public_key(kid).await?)
    }
}

impl Subject for KeySubject {
    fn identifier(&self) -> Result<String> {
        Ok(self.document.id.clone())
    }
}

/// This [`KeyValidator`] implements the [`Verify`] trait and can be used as a validator for a [`RelyingParty`]. It uses
/// the 'key' DID method.
#[derive(Default)]
pub struct KeyValidator;

impl KeyValidator {
    pub fn new() -> Self {
        KeyValidator {}
    }
}

#[async_trait]
impl Verify for KeyValidator {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        Ok(resolve_public_key(kid).await?)
    }
}

/// Resolves the public key from the given key identifier.
async fn resolve_public_key(kid: &str) -> Result<Vec<u8>> {
    let keypair = resolve(kid).map_err(|_| anyhow!("Failed to resolve the key identifier"))?;
    let authentication_method = keypair
        .get_did_document(Config::default())
        .authentication
        .and_then(|authentication_methods| authentication_methods.get(0).cloned())
        .ok_or(anyhow!("No public key found"))?;
    PatchedKeyPair::try_from(authentication_method.as_str())
        .map(|keypair| keypair.public_key_bytes())
        .map_err(|_| anyhow!("Failed to construct keypair from the default authentication method"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderManager, RelyingPartyManager};
    use std::sync::Arc;

//     #[tokio::test]
//     async fn test_key_subject() {
//         // Create a new subject.
//         let subject = KeySubject::new();

        // Create a new provider manager.
        let provider_manager = ProviderManager::new([Arc::new(subject)]).unwrap();

//         // Get a new SIOP request with response mode `post` for cross-device communication.
//         let request_url = "\
//             siopv2://idtoken?\
//                 scope=openid\
//                 &response_type=id_token\
//                 &client_id=did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF\
//                 &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
//                 &response_mode=post\
//                 &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
//                 %5B%22did%3Akey%22%5D%2C%0A%20%20%20%20\
//                 %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
//                 &nonce=n-0S6_WzA2Mj\
//             ";

        // Let the provider amanger validate the request.
        let request = provider_manager
            .validate_request(request_url.parse().unwrap())
            .await
            .unwrap();

        // Test whether the provider manager can generate a response for the request succesfully.
        let response = provider_manager
            .generate_response(request, Default::default())
            .await
            .unwrap();

//         // Create a new validator
//         let validator = KeyValidator::new();

        // Let the relying party validate the response.
        let relying_party_manager = RelyingPartyManager::new([Arc::new(KeySubject::new())]).unwrap();
        assert!(relying_party_manager.validate_response(&response).await.is_ok());
    }
}
