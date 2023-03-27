use anyhow::Result;
use identity_iota::{
    account::{Account, IdentitySetup, MethodContent},
    account_storage::KeyLocation,
    client::SharedPtr,
    did::{MethodRelationship, MethodScope},
    prelude::*,
};

use crate::subject_syntax_types::Subject;

use std::sync::Arc;

pub struct IotaSubject<C = Arc<Client>>
where
    C: SharedPtr<Client>,
{
    pub account: Account<C>,
}

impl Subject for IotaSubject {
    fn did(&self) -> String {
        self.account.did().to_string()
    }

    fn key_identifier(&self) -> String {
        self.account
            .document()
            .resolve_method("authentication-key", Some(MethodScope::authentication()))
            .and_then(|v| Some(v.id().to_string()))
            .unwrap()
    }

    fn sign(&self, message: &String) -> Result<Vec<u8>> {
        // Get the verification method from the DID document.
        let method = self
            .account
            .document()
            .resolve_method("authentication-key", None)
            .unwrap();
        let key_location = KeyLocation::from_verification_method(&method).unwrap();

        let proof_value = futures::executor::block_on(self.account.storage().key_sign(
            &self.account.did(),
            &key_location,
            message.as_bytes().to_vec(),
        ))?;

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

    pub async fn add_verification_method(
        &mut self,
        content: MethodContent,
        fragment: &str,
    ) -> Result<()> {
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
}
