use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::executor::block_on;
use identity_iota::{
    account::{Account, IdentitySetup, MethodContent},
    account_storage::KeyLocation,
    client::{Resolver, SharedPtr},
    did::{MethodRelationship, VerificationMethod},
    iota_core::{IotaDID, IotaDIDUrl},
    prelude::*,
};
use oid4vc_core::{authentication::sign::ExternalSign, Sign, Subject, Verify};
use std::sync::Arc;

pub struct IotaSubject<C = Arc<Client>>
where
    C: SharedPtr<Client>,
{
    pub account: Account<C>,
}

impl Sign for IotaSubject {
    fn sign(&self, message: &str) -> Result<Vec<u8>> {
        // Get the verification method for authentication from the DID document.
        let method = self
            .authentication_method()
            .ok_or_else(|| anyhow!("No authentication method found."))?;

        let key_location = KeyLocation::from_verification_method(method)?;

        let proof_value = block_on(self.account.storage().key_sign(
            self.account.did(),
            &key_location,
            message.as_bytes().to_vec(),
        ))?;

        Ok(proof_value.as_bytes().to_vec())
    }

    fn key_id(&self) -> Option<String> {
        self.authentication_method().map(|method| method.id().to_string())
    }

    // TODO: external sign method not supported yet for the IOTA method.
    fn external_signer(&self) -> Option<Arc<dyn ExternalSign>> {
        None
    }
}

/// `Subject` trait implementation for the IOTA method.
impl Subject for IotaSubject {
    fn identifier(&self) -> Result<String> {
        Ok(self.account.did().to_string())
    }
}

impl IotaSubject {
    pub async fn new() -> Result<Self> {
        Ok(IotaSubject {
            account: Account::builder()
                .storage(identity_iota::account_storage::MemStore::default())
                .create_identity(IdentitySetup::default())
                .await?,
        })
    }

    // Create a new `IotaSubject` from an existing `Account`.
    pub fn from_account(account: Account) -> Self {
        IotaSubject { account }
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

/// `Verify` trait implementation for the IOTA method.
#[async_trait]
impl Verify for IotaSubject {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        resolve_public_key(kid).await
    }
}

/// This [`IotaValidator`] implements the [`Verify`] trait and can be used as a validator for a [`RelyingParty`]. It uses
/// the 'iota' DID method.
#[derive(Default)]
pub struct IotaValidator;

impl IotaValidator {
    pub fn new() -> Self {
        IotaValidator {}
    }
}

#[async_trait]
impl Verify for IotaValidator {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        resolve_public_key(kid).await
    }
}

async fn resolve_public_key(kid: &str) -> Result<Vec<u8>> {
    let did_url = IotaDIDUrl::parse(kid)?;

    let did = did_url.did();
    let fragment = did_url.fragment().ok_or_else(|| anyhow!("No fragment found."))?;

    let resolver: Resolver = Resolver::new().await?;

    let document = resolver.resolve(did).await?.document;
    let method = document
        .resolve_method(fragment, None)
        .ok_or_else(|| anyhow!("No method found."))?;

    Ok(method.data().try_decode()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderManager, RelyingPartyManager};
    use chrono::{Duration, Utc};
    use identity_iota::{account::MethodContent, did::MethodRelationship};
    use oid4vc_core::DidMethod;
    use siopv2::{
        relying_party::ResponseItems, request::ResponseType, scope::ScopeValue, AuthorizationRequest, ClientMetadata,
        RequestUrl, Scope, StandardClaimsValues,
    };
    use std::str::FromStr;

    const AUTHENTICATION_KEY: &'static str = "authentication-key";

    #[tokio::test]
    async fn test_iota_subject() {
        let mut subject = IotaSubject::new().await.unwrap();
        println!("Created new IOTA subject: {:?}", subject.identifier().unwrap());

        // Add a new verification method using the Ed25519 algorithm.
        subject
            .add_verification_method(MethodContent::GenerateEd25519, AUTHENTICATION_KEY)
            .await
            .unwrap();
        println!("Added new verification method: {:?}", AUTHENTICATION_KEY);

        // Add the 'authentication' method relationship to the new verification method.
        subject
            .add_verification_relationships(AUTHENTICATION_KEY, vec![MethodRelationship::Authentication])
            .await
            .unwrap();
        println!(
            "Added 'authentication' relationship to verification method: {:?}",
            AUTHENTICATION_KEY
        );

        // Create a new provider manager.
        let provider_manager = ProviderManager::new([Arc::new(subject)]).unwrap();
        println!("Created new provider using the new IOTA subject");

        // Create a new RequestUrl with response mode `post` for cross-device communication.
        let request: AuthorizationRequest = RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:iota:4WfYF3te6X2Mm6aK6xK2hGrDJpVYAAM1NDA6HFgswsvt".to_owned())
            .scope(Scope::from(vec![ScopeValue::OpenId, ScopeValue::Phone]))
            .redirect_uri(
                format!("http://127.0.0.1:4200/redirect_uri")
                    .parse::<url::Url>()
                    .unwrap(),
            )
            .response_mode("post".to_owned())
            .client_metadata(
                ClientMetadata::default()
                    .with_subject_syntax_types_supported(vec![DidMethod::from_str("did:iota").unwrap().into()]),
            )
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .nonce("n-0S6_WzA2Mj".to_owned())
            .build()
            .and_then(TryInto::try_into)
            .unwrap();

        // The provider generates a signed SIOP response from the new SIOP request.
        let response = provider_manager
            .generate_response(request, StandardClaimsValues::default(), None, None)
            .unwrap();
        println!("Generated SIOP response based on the SIOP request: {:#?}", response);

        // Let the relying party manager validate the response.
        let relying_party_manager = RelyingPartyManager::new([Arc::new(IotaSubject::new().await.unwrap())]).unwrap();
        let ResponseItems { id_token, .. } = relying_party_manager.validate_response(&response).await.unwrap();
        println!("Validated SIOP response: {:#?}", id_token);
    }
}
