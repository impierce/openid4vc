use crate::siopv2::SIOPv2;
use anyhow::Result;
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::{
    authentication::subject::SigningSubject,
    authorization_request::{AuthorizationRequest, Object},
    authorization_response::AuthorizationResponse,
    jwt,
    openid4vc_extension::{Extension, ResponseHandle},
    Decoder,
};
use std::collections::HashMap;

pub struct RelyingParty {
    // TODO: Strictly speaking a relying party doesn't need to have a [`Subject`]. It just needs methods to
    // sign and verify tokens. For simplicity we use a [`Subject`] here for now but we should consider a cleaner solution.
    pub subject: SigningSubject,
    pub sessions: HashMap<(String, String), AuthorizationRequest<Object<SIOPv2>>>,
}

impl RelyingParty {
    // TODO: Use RelyingPartyBuilder instead.
    pub fn new(subject: SigningSubject) -> Result<Self> {
        Ok(RelyingParty {
            subject,
            sessions: HashMap::new(),
        })
    }

    pub fn encode<E: Extension>(&self, authorization_request: &AuthorizationRequest<Object<E>>) -> Result<String> {
        jwt::encode(
            self.subject.clone(),
            Header::new(Algorithm::EdDSA),
            authorization_request,
        )
    }

    /// Validates a [`AuthorizationResponse`] by decoding the header of the id_token, fetching the public key corresponding to
    /// the key identifier and finally decoding the id_token using the public key and by validating the signature.
    pub async fn validate_response<E: Extension>(
        &self,
        authorization_response: &AuthorizationResponse<E>,
        decoder: Decoder,
    ) -> Result<<E::ResponseHandle as ResponseHandle>::ResponseItem> {
        E::decode_authorization_response(decoder, authorization_response).await
    }
}
