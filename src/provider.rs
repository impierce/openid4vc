use std::str::FromStr;

use anyhow::Result;
use serde::Serialize;

use crate::{
    subject_syntax_types::{Subject, SubjectSyntaxType},
    IdToken, JsonWebToken, SiopRequest, SiopResponse,
};

/// A Self-Issued OpenID Provider (SIOP), which is responsible for generating and signing [`IdToken`]'s in response to
/// [`SiopRequest`]'s from [crate::relying_party::RelyingParty]'s (RPs). The [`Provider`] acts as a trusted intermediary between the RPs and
/// the user who is trying to authenticate.
pub struct Provider<S>
where
    S: Subject,
{
    pub subject: S,
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
            subject_syntax_types_supported: vec![],
        })
    }

    pub fn add_subject_syntax_type(&mut self, subject_syntax_type: SubjectSyntaxType) {
        self.subject_syntax_types_supported.push(subject_syntax_type);
    }

    pub fn generate_response(&mut self, request: SiopRequest) -> Result<SiopResponse> {
        if request.subject_syntax_types_supported().iter().any(|sst| {
            self.subject_syntax_types_supported
                .contains(&SubjectSyntaxType::from_str(sst).unwrap())
        }) {
            if request.is_cross_device_request() {
                if let Some(_redirect_uri) = request.redirect_uri() {
                    let id_token = IdToken::new(
                        self.subject.did(),
                        self.subject.did(),
                        request.client_id().clone(),
                        request.nonce().clone(),
                    );

                    let kid = self.subject.key_identifier().unwrap();

                    let jwt = JsonWebToken::new(id_token).kid(kid);

                    let message = [base64_url_encode(&jwt.header)?, base64_url_encode(&jwt.payload)?].join(".");

                    let proof_value = self.subject.sign(&message)?;
                    let signature = base64_url::encode(proof_value.as_slice());
                    let id_token = [message, signature].join(".");

                    return Ok(SiopResponse::new(id_token));
                } else {
                    panic!("There is no redirect_uri parameter!");
                }
            }
        }
        todo!();
    }

    pub async fn send_response(&self, response: SiopResponse, redirect_uri: String) {
        let client = reqwest::Client::new();
        let builder = client.post(redirect_uri).form(&response);
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
    use crate::subject_syntax_types::did_methods::DidMethod;

    const ED25519_PRIVATE_KEY: [u8; 64] = [
        35, 158, 92, 18, 248, 210, 204, 33, 101, 4, 120, 7, 202, 186, 2, 240, 74, 174, 161, 215, 200, 234, 164, 123,
        239, 225, 243, 78, 189, 217, 211, 97, 35, 158, 92, 18, 248, 210, 204, 33, 101, 4, 120, 7, 202, 186, 2, 240, 74,
        174, 161, 215, 200, 234, 164, 123, 239, 225, 243, 78, 189, 217, 211, 97,
    ];

    struct MockSubject;

    impl MockSubject {
        fn new() -> Self {
            MockSubject {}
        }
    }

    impl Subject for MockSubject {
        fn did(&self) -> String {
            "did:mock:123".to_string()
        }

        fn key_identifier(&self) -> Option<String> {
            Some("key_identifier".to_string())
        }

        fn sign(&self, message: &String) -> Result<Vec<u8>> {
            use ed25519_dalek::{Signature, Signer};
            let keypair = ed25519_dalek::Keypair::from_bytes(&ED25519_PRIVATE_KEY).unwrap();
            let signature: Signature = keypair.sign(message.as_bytes());
            Ok(signature.to_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn test_provider() {
        // Create a new subject.
        let subject = MockSubject::new();

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

        // // Let the relying party validate the response.
        // let relying_party = RelyingParty::new();
        // let id_token = relying_party.validate_response(&response).await.unwrap();
        // dbg!(&id_token);
    }
}
