use std::str::FromStr;

use anyhow::Result;
use serde::Serialize;

use crate::id_token::IdToken;
use crate::jwt::JsonWebToken;
use crate::request::SiopRequest;
use crate::response::SiopResponse;
use crate::subject_syntax_types::{Subject, SubjectSyntaxType};

// redirct_uri and jwt should not be here, use some kind of response/request config struct instead.
pub struct Provider<S>
where
    S: Subject,
{
    subject: S,
    redirect_uri: Option<String>,
    jwt: Option<JsonWebToken>,
    subject_syntax_types_supported: Vec<SubjectSyntaxType>,
}

impl<S> Provider<S>
where
    S: Subject,
{
    // TODO: Use ProviderBuilder instead.
    pub async fn new(subject: S) -> Result<Self> {
        Ok(Provider {
            subject,
            redirect_uri: None,
            jwt: None,
            subject_syntax_types_supported: vec![],
        })
    }

    // pub async fn new_with_private_key(private_key: PrivateKey) -> Result<Self> {
    //     let mut account: Account = Account::builder()
    //         // TODO: Only use MemStore for testing purposes.
    //         .storage(identity_iota::account_storage::MemStore::default())
    //         .autopublish(false)
    //         .create_identity(IdentitySetup::default().private_key(private_key))
    //         .await?;

    //     // account.fetch_document().await?;

    //     Ok(Provider {
    //         account,
    //         redirect_uri: None,
    //         jwt: None,
    //         subject_syntax_types_supported: vec![],
    //     })
    // }

    pub fn add_subject_syntax_type(&mut self, subject_syntax_type: SubjectSyntaxType) {
        self.subject_syntax_types_supported
            .push(subject_syntax_type);
    }

    pub fn generate_response(&mut self, verification_method: &str, request: SiopRequest) -> () {
        if request.subject_syntax_types_supported().iter().any(|sst| {
            self.subject_syntax_types_supported
                .contains(&SubjectSyntaxType::from_str(sst).unwrap())
        }) {
            if request.is_cross_device_request() {
                if let Some(redirect_uri) = request.redirect_uri() {
                    let id_token = IdToken::new(
                        self.subject.did(),
                        self.subject.did(),
                        request.client_id().clone(),
                        request.nonce().clone(),
                    );

                    let kid = self.subject.key_identifier();

                    let jwt = JsonWebToken::new(id_token).kid(kid);
                    self.redirect_uri.insert(redirect_uri.clone());
                    self.jwt.insert(jwt);
                } else {
                    panic!("There is no redirect_uri parameter!");
                }
                return ();
            }
        }

        todo!();
    }

    // Sign the response.
    pub async fn sign_response(&mut self, verification_method: &str) -> Result<SiopResponse> {
        let message = [
            base64_url_encode(&self.jwt.as_ref().unwrap().header)?,
            base64_url_encode(&self.jwt.as_ref().unwrap().payload)?,
        ]
        .join(".");

        let proof_value = self.subject.sign(&message)?;
        let signature = base64_url::encode(proof_value.as_slice());
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

fn base64_url_encode<T>(value: &T) -> Result<String>
where
    T: ?Sized + Serialize,
{
    Ok(base64_url::encode(serde_json::to_vec(value)?.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relying_party::RelyingParty;
    use crate::subject_syntax_types::did_methods::{iota::IotaSubject, DidMethod};
    use crate::test_utils::relying_party;
    use identity_iota::{account::MethodContent, did::MethodRelationship};
    use tokio::runtime::Runtime;

    const PRIVATE_KEY: [u8; 32] = [
        35, 158, 92, 18, 248, 210, 204, 33, 101, 4, 120, 7, 202, 186, 2, 240, 74, 174, 161, 215,
        200, 234, 164, 123, 239, 225, 243, 78, 189, 217, 211, 97,
    ];

    const AUTHENTICATION_KEY: &'static str = "authentication-key";

    #[test]
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
    async fn test_provider() {
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
        dbg!(provider.subject.account.document());

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

        // The provider generates a SIOP response from the new SIOP request.
        provider.generate_response(AUTHENTICATION_KEY, request);

        // The provider signs the response it created.
        let response = provider.sign_response(AUTHENTICATION_KEY).await.unwrap();
        dbg!(&response);

        // // Finally, the provider sends the signed response to the designated endpoint via an HTTP POST request.
        // provider.send_response(response).await;

        // Let the relying party validate the response.
        let relying_party = RelyingParty::new();
        let id_token = relying_party.validate_response(&response).await.unwrap();
        dbg!(&id_token);

        // // Optional: remove the authentication verivication method.
        provider
            .subject
            .remove_verification_relationships(
                AUTHENTICATION_KEY,
                vec![MethodRelationship::Authentication],
            )
            .await
            .unwrap();

        provider
            .subject
            .remove_verification_method(AUTHENTICATION_KEY)
            .await
            .unwrap();
    }
}
