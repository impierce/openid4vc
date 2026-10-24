use anyhow::{anyhow, Result};
use async_trait::async_trait;
use identity_kit::{
    did::{Did, DidUrl},
    jose::{JwsAlgorithm, KeyType, Signer as _},
    keys::{InMemoryKeyStore, KeyId, KeySigner, KeySpec, KeyStore},
    methods::{key::KeyFormat, DidKey},
};
use jsonwebtoken::Algorithm;
use oid4vc_core::{authentication::sign::ExternalSign, Sign, Subject, Verify};
use std::sync::Arc;

/// This [`KeySubject`] implements the [`Subject`] trait and can be used as a subject for a [`siopv2::Provider`]. It uses the
/// 'key' DID method over an Ed25519 key in an identity-kit [`KeyStore`].
pub struct KeySubject {
    signer: KeySigner<Arc<dyn KeyStore>>,
    did: Did,
    key_id: DidUrl,
    external_signer: Option<Arc<dyn ExternalSign>>,
}

/// Leaves out the signer.
impl std::fmt::Debug for KeySubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySubject")
            .field("did", &self.did)
            .field("key_id", &self.key_id)
            .field("external_signer", &self.external_signer)
            .finish_non_exhaustive()
    }
}

impl KeySubject {
    /// Creates a new [`KeySubject`] over a new Ed25519 key in an [`InMemoryKeyStore`].
    pub async fn new() -> Result<Self> {
        let store = InMemoryKeyStore::new();
        let key = store
            .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
            .await?;
        Self::from_key_store(Arc::new(store), key, None).await
    }

    /// Creates a new [`KeySubject`] over the Ed25519 `key` of `store`, whose `did:key` is derived from the key's public
    /// JWK. With an `external_signer`, signatures come from it instead of the store.
    pub async fn from_key_store(
        store: Arc<dyn KeyStore>,
        key: KeyId,
        external_signer: Option<Arc<dyn ExternalSign>>,
    ) -> Result<Self> {
        let signer = KeySigner::new(store, key, JwsAlgorithm::EdDSA).await?;
        let did = DidKey::did(signer.public_jwk())?;
        let key_id = did.join(&format!("#{}", did.method_specific_id()))?;
        Ok(KeySubject {
            signer,
            did,
            key_id,
            external_signer,
        })
    }
}

#[async_trait]
impl Sign for KeySubject {
    async fn key_id(&self, _subject_syntax_type: &str, _algorithm: Algorithm) -> Option<String> {
        Some(self.key_id.to_string())
    }

    async fn sign(&self, message: &str, _subject_syntax_type: &str, _algorithm: Algorithm) -> Result<Vec<u8>> {
        match self.external_signer() {
            Some(external_signer) => external_signer.sign(message),
            None => Ok(self.signer.sign(message.as_bytes()).await?),
        }
    }

    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>> {
        self.external_signer.clone()
    }
}

#[async_trait]
impl Verify for KeySubject {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        resolve_public_key(kid)
    }
}

#[async_trait]
impl Subject for KeySubject {
    async fn identifier(&self, _subject_syntax_type: &str, _algorithm: Algorithm) -> Result<String> {
        Ok(self.did.to_string())
    }
}

/// This [`KeyValidator`] implements the [`Verify`] trait and can be used as a validator for a [`siopv2::RelyingParty`]. It uses
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
        resolve_public_key(kid)
    }
}

/// Resolves the Ed25519 public key that the key identifier, a DID URL into a `did:key` document, names.
fn resolve_public_key(kid: &str) -> Result<Vec<u8>> {
    let kid = DidUrl::parse(kid)?;
    let document = DidKey::new().with_format(KeyFormat::JsonWebKey).document(kid.did())?;
    let jwk = document
        .verification_method
        .iter()
        .find(|method| method.id == kid)
        .and_then(|method| method.public_key_jwk())
        .ok_or(anyhow!("No public key found for `{kid}`"))?;
    Ok(jwk.ed25519_public_bytes()?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderManager, RelyingPartyManager};
    use jsonwebtoken::Algorithm;
    use oid4vc_core::authorization_request::{AuthorizationRequest, Object};
    use siopv2::siopv2::SIOPv2;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_key_subject() {
        // Create a new subject.
        let subject = KeySubject::new().await.unwrap();

        // Create a new provider manager.
        let provider_manager =
            ProviderManager::new(Arc::new(subject), vec!["did:key"], vec![Algorithm::EdDSA]).unwrap();

        // Get a new SIOP authorization_request with response mode `direct_post` for cross-device communication.
        let request_url = "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=direct_post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Akey%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ";

        // Let the provider manager validate the authorization_request.
        let authorization_request = provider_manager
            .validate_request(request_url.to_string())
            .await
            .unwrap();

        let authorization_request =
            AuthorizationRequest::<Object<SIOPv2>>::from_generic(&authorization_request).unwrap();

        // Test whether the provider manager can generate a authorization_response for the authorization_request succesfully.
        let authorization_response = provider_manager
            .generate_response(&authorization_request, Default::default())
            .await
            .unwrap();

        // Let the relying party validate the authorization_response.
        let relying_party_manager = RelyingPartyManager::new(
            Arc::new(KeySubject::new().await.unwrap()),
            "did:key",
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        #[allow(deprecated)]
        let res = relying_party_manager.validate_response(&authorization_response).await;
        assert!(res.is_ok());
    }
}
