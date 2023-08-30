use oid4vc_core::{authorization_request::Extension, serialize_unit_struct};
use serde::{Deserialize, Serialize};

use crate::{ClaimRequests, ClientMetadata, Scope};

#[derive(Debug)]
pub struct IdToken;
serialize_unit_struct!("id_token", IdToken);

#[derive(Serialize, Deserialize, Debug)]
pub struct SIOPv2;
impl Extension for SIOPv2 {
    type ResponseType = IdToken;
    type AuthorizationRequest = SIOPv2AuthorizationRequestParameters;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SIOPv2AuthorizationRequestParameters {
    // TODO: make generic Scope and add it to `AuthorizationRequestObject`.
    pub scope: Scope,
    pub response_mode: Option<String>,
    pub nonce: String,
    pub claims: Option<ClaimRequests>,
    // TODO: impl client_metadata_uri.
    pub client_metadata: Option<ClientMetadata>,
}
