use crate::{provider::SigningSubject, AuthorizationRequest, AuthorizationResponse, IdToken};
use anyhow::Result;
use oid4vc_core::{jwt, Decoder};
use oid4vci::VerifiableCredentialJwt;
use std::collections::HashMap;

pub struct RelyingParty {
    // TODO: Strictly speaking a relying party doesn't need to have a [`Subject`]. It just needs methods to
    // sign and verify tokens. For simplicity we use a [`Subject`] here for now but we should consider a cleaner solution.
    pub subject: SigningSubject,
    pub sessions: HashMap<(String, String), AuthorizationRequest>,
}

impl RelyingParty {
    // TODO: Use RelyingPartyBuilder instead.
    pub fn new(subject: SigningSubject) -> Result<Self> {
        Ok(RelyingParty {
            subject,
            sessions: HashMap::new(),
        })
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
    pub async fn validate_response(&self, response: &AuthorizationResponse, decoder: Decoder) -> Result<ResponseItems> {
        let token = response
            .id_token()
            .to_owned()
            .ok_or(anyhow::anyhow!("No id_token parameter in response"))?;
        let id_token = decoder.decode(token).await?;

        // Validate the vp_token if present.
        let credentials: Option<Vec<VerifiableCredentialJwt>> =
            if let Some(oid4vp_response) = response.oid4vp_response() {
                Some(oid4vp_response.decode(&decoder).await?)
            } else {
                None
            };

        Ok(ResponseItems {
            id_token,
            verifiable_credentials: credentials,
        })
    }
}

pub struct ResponseItems {
    pub id_token: IdToken,
    pub verifiable_credentials: Option<Vec<VerifiableCredentialJwt>>,
}
