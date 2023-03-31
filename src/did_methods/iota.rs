use anyhow::Result;
use async_trait::async_trait;
use identity_iota::{
    account::{Account, IdentitySetup, MethodContent},
    account_storage::KeyLocation,
    client::{Resolver, SharedPtr},
    did::{MethodRelationship, VerificationMethod},
    iota_core::{IotaDID, IotaDIDUrl},
    prelude::*,
};

use crate::{provider::Subject, relying_party::Validator};

use std::sync::Arc;

pub struct IotaSubject<C = Arc<Client>>
where
    C: SharedPtr<Client>,
{
    pub account: Account<C>,
}

#[async_trait]
impl Subject for IotaSubject {
    fn did(&self) -> String {
        self.account.did().to_string()
    }

    fn key_identifier(&self) -> Option<String> {
        self.authentication_method()
            .and_then(|verification_method| Some(verification_method.id().to_string()))
    }

    async fn sign(&self, message: &String) -> Result<Vec<u8>> {
        // Get the verification method for authentication from the DID document.
        let method = self.authentication_method().unwrap();

        let key_location = KeyLocation::from_verification_method(&method).unwrap();

        let proof_value = self
            .account
            .storage()
            .key_sign(&self.account.did(), &key_location, message.as_bytes().to_vec())
            .await?;

        Ok(proof_value.as_bytes().to_vec())
    }
}

impl IotaSubject {
    pub async fn new() -> Result<Self> {
        Ok(IotaSubject {
            account: Account::builder()
                // TODO: Only use MemStore for testing purposes.
                .storage(identity_iota::account_storage::MemStore::default())
                .create_identity(IdentitySetup::default())
                .await?,
        })
    }

    pub async fn add_verification_method(&mut self, content: MethodContent, fragment: &str) -> Result<()> {
        Ok(self
            .account
            .update_identity()
            .create_method()
            .content(content)
            .fragment(fragment)
            .apply()
            .await?)
    }

    pub async fn remove_verification_method(&mut self, fragment: &str) -> Result<()> {
        Ok(self
            .account
            .update_identity()
            .delete_method()
            .fragment(fragment)
            .apply()
            .await?)
    }

    pub async fn add_verification_relationships(
        &mut self,
        fragment: &str,
        relationships: Vec<MethodRelationship>,
    ) -> Result<()> {
        Ok(self
            .account
            .update_identity()
            .attach_method_relationship()
            .fragment(fragment)
            .relationships(relationships)
            .apply()
            .await?)
    }

    pub async fn remove_verification_relationships(
        &mut self,
        fragment: &str,
        relationships: Vec<MethodRelationship>,
    ) -> Result<()> {
        Ok(self
            .account
            .update_identity()
            .detach_method_relationship()
            .fragment(fragment)
            .relationships(relationships)
            .apply()
            .await?)
    }

    pub fn authentication_method(&self) -> Option<&VerificationMethod<IotaDID>> {
        self.account
            .document()
            .core_document()
            .authentication()
            .head()
            .and_then(|method_ref| self.account.document().core_document().resolve_method_ref(method_ref))
    }
}

pub struct IotaValidator;

impl IotaValidator {
    pub fn new() -> Self {
        IotaValidator {}
    }
}

#[async_trait]
impl Validator for IotaValidator {
    async fn public_key(&self, kid: &String) -> Result<Vec<u8>> {
        let did_url = IotaDIDUrl::parse(kid.as_str())?;

        let did = did_url.did();
        let fragment = did_url.fragment().unwrap();

        let resolver: Resolver = Resolver::new().await?;

        let document = resolver.resolve(did).await?.document;
        let method = document.resolve_method(fragment, None).unwrap();

        Ok(method.data().try_decode()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdToken, Provider, RelyingParty, SiopRequest};
    use identity_iota::{account::MethodContent, did::MethodRelationship};

    const AUTHENTICATION_KEY: &'static str = "authentication-key";

    #[tokio::test]
    async fn test_iota_subject() {
        let mut subject = IotaSubject::new().await.unwrap();

        // Add a new verification method using the Ed25519 algorithm.
        subject
            .add_verification_method(MethodContent::GenerateEd25519, AUTHENTICATION_KEY)
            .await
            .unwrap();

        // Add the 'authentication' method relationship to the new verification method.
        subject
            .add_verification_relationships(AUTHENTICATION_KEY, vec![MethodRelationship::Authentication])
            .await
            .unwrap();

        // Create a new provider.
        let mut provider = Provider::new(subject).await.unwrap();

        // Get a new SIOP request with response mode `post` for cross-device communication.
        let request: SiopRequest = serde_qs::from_str(
            "\
                response_type=id_token\
                &response_mode=post\
                &client_id=did:iota:4WfYF3te6X2Mm6aK6xK2hGrDJpVYAAM1NDA6HFgswsvt\
                &redirect_uri=http://127.0.0.1:4200/redirect_uri\
                &scope=openid\
                &nonce=n-0S6_WzA2Mj\
                &subject_syntax_types_supported[0]=did%3Aiota\
            ",
        )
        .unwrap();

        // The provider generates a signed SIOP response from the new SIOP request.
        let response = provider.generate_response(request).await.unwrap();

        // Let the relying party validate the response.
        let relying_party = RelyingParty::new(IotaValidator::new());
        let id_token = relying_party.validate_response(&response).await.unwrap();

        let IdToken { aud, nonce, .. } = IdToken::new(
            "".to_string(),
            "".to_string(),
            "did:iota:4WfYF3te6X2Mm6aK6xK2hGrDJpVYAAM1NDA6HFgswsvt".to_string(),
            "n-0S6_WzA2Mj".to_string(),
        );
        assert_eq!(id_token.iss, id_token.sub);
        assert_eq!(id_token.aud, aud);
        assert_eq!(id_token.nonce, nonce);

        // Optional: remove the authentication verivication method.
        // provider
        //     .subject
        //     .remove_verification_relationships(
        //         AUTHENTICATION_KEY,
        //         vec![MethodRelationship::Authentication],
        //     )
        //     .await
        //     .unwrap();

        // provider
        //     .subject
        //     .remove_verification_method(AUTHENTICATION_KEY)
        //     .await
        //     .unwrap();
    }
}
