use std::sync::Arc;

use anyhow::Result;
use identity_core::crypto::{GetSignature, PrivateKey, ProofOptions};
use identity_iota::{
    account::{Account, IdentitySetup, MethodContent},
    client::SharedPtr,
    did::MethodRelationship,
    prelude::*,
};

use crate::id_token::IdToken;
use crate::jwt::{JsonWebToken, TempWrapper};
use crate::request::SiopRequest;
use crate::response::SiopResponse;

// redirct_uri and jwt should not be here, use some kind of response/request config struct instead.
pub struct Provider<C = Arc<Client>>
where
    C: SharedPtr<Client>,
{
    account: Account<C>,
    redirect_uri: Option<String>,
    jwt: Option<JsonWebToken>,
}

impl Provider {
    // TODO: Use ProviderBuilder instead.
    pub async fn new() -> Result<Self> {
        let account: Account = Account::builder()
            // TODO: Only use MemStore for testing purposes.
            .storage(identity_iota::account_storage::MemStore::default())
            .create_identity(IdentitySetup::default())
            .await?;
        Ok(Provider {
            account,
            redirect_uri: None,
            jwt: None,
        })
    }

    pub async fn new_with_private_key(private_key: PrivateKey) -> Result<Self> {
        let account: Account = Account::builder()
            // TODO: Only use MemStore for testing purposes.
            .storage(identity_iota::account_storage::MemStore::default())
            .create_identity(IdentitySetup::default().private_key(private_key))
            .await?;
        Ok(Provider {
            account,
            redirect_uri: None,
            jwt: None,
        })
    }

    pub fn generate_response(&mut self, request: SiopRequest) -> () {
        if request.is_cross_device_request() {
            if let Some(redirect_uri) = request.redirect_uri() {
                let id_token = IdToken::new(
                    self.account.did().to_string(),
                    self.account.did().to_string(),
                    request.client_id().clone(),
                    request.nonce().clone(),
                );
                let jwt = JsonWebToken::new(id_token);
                self.redirect_uri.insert(redirect_uri.clone());
                self.jwt.insert(jwt);
            } else {
                panic!("There is no redirect_uri parameter!");
            }
            return ();
        }
        todo!();
    }

    pub async fn add_verification_method(
        &mut self,
        content: MethodContent,
        fragment: &str,
    ) -> Result<()> {
        self.account
            .update_identity()
            .create_method()
            .content(content)
            .fragment(fragment)
            .apply()
            .await?;
        Ok(())
    }

    pub async fn add_verification_relationships(
        &mut self,
        fragment: &str,
        relationships: Vec<MethodRelationship>,
    ) -> Result<()> {
        self.account
            .update_identity()
            .attach_method_relationship()
            .fragment(fragment)
            .relationships(relationships)
            .apply()
            .await?;
        Ok(())
    }

    // TODO: Needs a lot of refactoring.
    pub async fn sign_response(&mut self, verification_method: &str) -> Result<SiopResponse> {
        use base64::Engine;

        let base64_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&serde_json::to_string(&self.jwt.as_ref().unwrap().header).unwrap());
        let base64_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&serde_json::to_string(&self.jwt.as_ref().unwrap().payload).unwrap());

        let message = [base64_header, base64_payload].join(".");

        let mut temp_wrapper = TempWrapper {
            message: message.clone(),
            signature: None,
        };

        self.account
            .sign(
                verification_method,
                &mut temp_wrapper,
                ProofOptions::default(),
            )
            .await?;

        let signature = temp_wrapper
            .signature()
            .unwrap()
            .value()
            .clone()
            .into_string();

        let id_token = [message, signature].join(".");

        Ok(SiopResponse::new(id_token))
    }

    async fn send_response(&self, response: SiopResponse) {
        let client = reqwest::Client::new();
        let builder = client
            .post(self.redirect_uri.as_ref().unwrap())
            .form(&response);
        builder.send().await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE_KEY: [u8; 32] = [
        35, 158, 92, 18, 248, 210, 204, 33, 101, 4, 120, 7, 202, 186, 2, 240, 74, 174, 161, 215,
        200, 234, 164, 123, 239, 225, 243, 78, 189, 217, 211, 97,
    ];

    #[tokio::test]
    async fn test_provider() {
        // TODO: Find a way to fetch an existing account.
        let mut provider = Provider::new_with_private_key(PrivateKey::from(PRIVATE_KEY.to_vec()))
            .await
            .unwrap();

        provider
            .add_verification_method(MethodContent::GenerateEd25519, "authentication-key")
            .await
            .unwrap();

        provider
            .add_verification_relationships(
                "authentication-key",
                vec![MethodRelationship::Authentication],
            )
            .await
            .unwrap();

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
        dbg!(&request);

        provider.generate_response(request);
        let response = provider.sign_response("authentication-key").await.unwrap();
        dbg!(&response);

        // provider.send_response(response).await;
    }
}
