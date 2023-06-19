use crate::{jwt, provider::SigningSubject, AuthorizationRequest, AuthorizationResponse, Decoder, IdToken};
use anyhow::Result;

pub struct RelyingParty {
    pub subject: SigningSubject,
}

impl RelyingParty {
    // TODO: Use RelyingPartyBuilder instead.
    pub fn new(subject: SigningSubject) -> Result<Self> {
        Ok(RelyingParty { subject })
    }

    pub async fn encode(&self, request: &AuthorizationRequest) -> Result<String> {
        jwt::encode(self.subject.clone(), request).await
    }

    /// Validates a [`AuthorizationResponse`] by decoding the header of the id_token, fetching the public key corresponding to
    /// the key identifier and finally decoding the id_token using the public key and by validating the signature.
    // TODO: Validate the claims in the id_token as described here:
    // https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-id-token-valida
    pub async fn validate_response(&self, response: &AuthorizationResponse, decoder: Decoder) -> Result<IdToken> {
        let token = response
            .id_token()
            .to_owned()
            .ok_or(anyhow::anyhow!("No id_token parameter in response"))?;
        decoder.decode(token).await
    }
}
