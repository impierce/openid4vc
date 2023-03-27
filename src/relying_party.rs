use crate::id_token::IdToken;
use crate::response::SiopResponse;
use anyhow::Result;
use identity_iota::{client::Resolver, iota_core::IotaDIDUrl};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

pub struct RelyingParty {}

impl RelyingParty {
    pub fn new() -> Self {
        RelyingParty {}
    }

    pub async fn validate_response(&self, response: &SiopResponse) -> Result<IdToken> {
        let id_token = response.id_token.clone();
        let header = decode_header(id_token.as_str())?;
        let kid = header.kid.unwrap().clone();

        let did_url = IotaDIDUrl::parse(kid.as_str())?;

        let did = did_url.did();
        let fragment = did_url.fragment().unwrap();

        let resolver: Resolver = Resolver::new().await?;

        let document = resolver.resolve(did).await?.document;
        let method = document.resolve_method(fragment, None).unwrap();

        let public_key = method.data().try_decode()?;

        let key = DecodingKey::from_ed_der(&public_key.as_slice());
        let token_data =
            decode::<IdToken>(id_token.as_str(), &key, &Validation::new(Algorithm::EdDSA))?;

        let id_token = token_data.claims;

        Ok(id_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relying_party() {
        let response = SiopResponse {
            id_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDppb3RhOkFxY1M5RVdEQU5LYmJLOENBSENVWjZnd1ZnQ3JwYmdiWHRqZ0t6M0R5dTk0I2F1dGhlbnRpY2F0aW9uLWtleSJ9.eyJpc3MiOiJkaWQ6aW90YTpBcWNTOUVXREFOS2JiSzhDQUhDVVo2Z3dWZ0NycGJnYlh0amdLejNEeXU5NCIsInN1YiI6ImRpZDppb3RhOkFxY1M5RVdEQU5LYmJLOENBSENVWjZnd1ZnQ3JwYmdiWHRqZ0t6M0R5dTk0IiwiYXVkIjoiZGlkOmlvdGE6NFdmWUYzdGU2WDJNbTZhSzZ4SzJoR3JESnBWWUFBTTFOREE2SEZnc3dzdnQiLCJleHAiOjE2Nzk4NTQ4MzUsImlhdCI6MTY3OTg1NDIzNSwibm9uY2UiOiJuLTBTNl9XekEyTWoifQ.a82eOyPPSQKdoMZCxqo9x7yZlQ7FOmlPCm85dNGKNnO3z6R4ewoVBUgmAOpPuc7GmE0M62VI4ZgLCkWlAy2mCw".to_string()
        };

        let rp = RelyingParty::new();

        rp.validate_response(&response).await;
    }
}
