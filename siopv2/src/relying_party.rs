use crate::{
    jwt, provider::SigningSubject, response::Oid4vpParams, token::vp_token::VpToken, AuthorizationRequest,
    AuthorizationResponse, Decoder, IdToken,
};
use anyhow::Result;
use std::{str::FromStr, sync::Arc};

pub struct RelyingParty {
    // TODO: Strictly speaking a relying party doesn't need to have a [`Subject`]. It just needs methods to
    // sign and verify tokens. For simplicity we use a [`Subject`] here for now but we should consider a cleaner solution.
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
    // TODO: Needs a lot of refactoring. id_token validation and vp_token validation should be separate (moved to
    // seperate crates). Also in general vp_token needs proper validation (regarding presentation_submission) instead of
    // just validating the jwt.
    pub async fn validate_response(
        &self,
        response: &AuthorizationResponse,
        decoder: Decoder,
    ) -> Result<(IdToken, Option<VpToken>)> {
        let token = response
            .id_token()
            .to_owned()
            .ok_or(anyhow::anyhow!("No id_token parameter in response"))?;
        let id_token = decoder.decode(token).await?;

        // TODO: Currently this only validates the vp_token JWT (verifiable presentation). It should also validate the
        // actual individual verifiable credentials inside the verifiable presentation.
        let vp_token: Option<VpToken> = if let Some(oid4vp_response) = response.oid4vp_response() {
            match oid4vp_response {
                Oid4vpParams::Jwt { .. } => todo!(),
                Oid4vpParams::Params { vp_token, .. } => Some(decoder.decode(vp_token.to_owned()).await?),
            }
        } else {
            None
        };

        Ok((id_token, vp_token))
    }
}
