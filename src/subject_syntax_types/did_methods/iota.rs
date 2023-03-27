use anyhow::Result;
use identity_iota::{
    account::{Account, IdentitySetup, MethodContent},
    account_storage::KeyLocation,
    client::SharedPtr,
    did::{MethodRelationship, VerificationMethod},
    iota_core::IotaDID,
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

    fn key_identifier(&self) -> Option<String> {
        self.authentication_method()
            .and_then(|verification_method| Some(verification_method.id().to_string()))
    }

    fn sign(&self, message: &String) -> Result<Vec<u8>> {
        // Get the verification method for authentication from the DID document.
        let method = self.authentication_method().unwrap();

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

    pub fn authentication_method(&self) -> Option<&VerificationMethod<IotaDID>> {
        self.account
            .document()
            .core_document()
            .authentication()
            .head()
            .and_then(|method_ref| {
                self.account
                    .document()
                    .core_document()
                    .resolve_method_ref(method_ref)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;
    use crate::relying_party::RelyingParty;
    use crate::request::SiopRequest;
    use crate::subject_syntax_types::{did_methods::DidMethod, SubjectSyntaxType};
    use crate::test_utils::relying_party;
    use identity_iota::{account::MethodContent, did::MethodRelationship};
    use tokio::runtime::Runtime;

    const PRIVATE_KEY: [u8; 32] = [
        35, 158, 92, 18, 248, 210, 204, 33, 101, 4, 120, 7, 202, 186, 2, 240, 74, 174, 161, 215,
        200, 234, 164, 123, 239, 225, 243, 78, 189, 217, 211, 97,
    ];

    const AUTHENTICATION_KEY: &'static str = "authentication-key";

    // #[test]
    fn test_create_request() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            tokio::spawn(async { relying_party().await });
            // tokio::spawn(async { test_provider().await });
        });

        // Wait for the axum server to get ready.
        std::thread::sleep(std::time::Duration::from_secs(80));
    }

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
            .add_verification_relationships(
                AUTHENTICATION_KEY,
                vec![MethodRelationship::Authentication],
            )
            .await
            .unwrap();

        // Create a new provider.
        let mut provider = Provider::new(subject).await.unwrap();

        provider.add_subject_syntax_type(SubjectSyntaxType::DID(DidMethod::Iota));

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
        let response = provider.generate_response(request).unwrap();
        dbg!(&response);

        // // Finally, the provider sends the signed response to the designated endpoint via an HTTP POST request.
        // provider.send_response(response).await;

        // Let the relying party validate the response.
        let relying_party = RelyingParty::new();
        let id_token = relying_party.validate_response(&response).await.unwrap();
        dbg!(&id_token);

        // // Optional: remove the authentication verivication method.
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
