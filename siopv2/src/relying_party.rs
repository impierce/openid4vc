use crate::{
    jwt, provider::SigningSubject, response::Oid4vpParams, token::vp_token::VpToken, AuthorizationRequest,
    AuthorizationResponse, Decoder, IdToken, VerifiableCredentialJwt,
};
use anyhow::Result;
use futures::{executor::block_on, future::join_all};

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
    // just validating the jwt. See: https://openid.bitbucket.io/connect/openid-4-verifiable-presentations-1_0.html#name-vp-token-validation
    pub async fn validate_response(
        &self,
        response: &AuthorizationResponse,
        decoder: Decoder,
    ) -> Result<(IdToken, Option<Vec<VerifiableCredentialJwt>>)> {
        let token = response
            .id_token()
            .to_owned()
            .ok_or(anyhow::anyhow!("No id_token parameter in response"))?;
        let id_token = decoder.decode(token).await?;

        // Validat the vp_token if present.
        let vp_token: Option<VpToken> = if let Some(oid4vp_response) = response.oid4vp_response() {
            match oid4vp_response {
                Oid4vpParams::Jwt { .. } => todo!(),
                Oid4vpParams::Params { vp_token, .. } => Some(decoder.decode(vp_token.to_owned()).await?),
            }
        } else {
            None
        };

        // Decode the verifiable credentials in the vp_token.
        let credentials = vp_token
            .map(|vp_token| {
                block_on(async move {
                    join_all(
                        vp_token
                            .verifiable_presentation()
                            .verifiable_credential
                            .iter()
                            .map(|vc| async { decoder.decode(vc.as_str().to_owned()).await }),
                    )
                    .await
                    .into_iter()
                    .collect::<Result<Vec<VerifiableCredentialJwt>>>()
                })
            })
            .transpose()?;

        Ok((id_token, credentials))
    }
}
