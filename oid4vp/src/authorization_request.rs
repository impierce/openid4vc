use crate::oid4vp::OID4VP;
use anyhow::{anyhow, Result};
use dif_presentation_exchange::PresentationDefinition;
use is_empty::IsEmpty;
use oid4vc_core::builder_fn;
use oid4vc_core::{
    authorization_request::{AuthorizationRequest, AuthorizationRequestObject},
    client_metadata::ClientMetadata,
    scope::Scope,
    RFC7519Claims,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct OID4VPAuthorizationRequestParameters {
    pub presentation_definition: PresentationDefinition,
    pub client_id_scheme: Option<String>,
    pub response_mode: Option<String>,
    pub scope: Option<Scope>,
    pub nonce: String,
    // TODO: impl client_metadata_uri.
    pub client_metadata: Option<ClientMetadata>,
}

#[derive(Debug, Default, IsEmpty)]
pub struct OID4VPAuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    presentation_definition: Option<PresentationDefinition>,
    client_id_scheme: Option<String>,
    client_id: Option<String>,
    request: Option<String>,
    request_uri: Option<url::Url>,
    redirect_uri: Option<url::Url>,
    state: Option<String>,
    scope: Option<Scope>,
    response_mode: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadata>,
}

impl OID4VPAuthorizationRequestBuilder {
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(request_uri, url::Url);
    builder_fn!(response_mode, String);
    builder_fn!(client_id, String);
    builder_fn!(scope, Scope);
    builder_fn!(redirect_uri, url::Url);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadata);
    builder_fn!(state, String);
    builder_fn!(presentation_definition, PresentationDefinition);

    pub fn build(mut self) -> Result<AuthorizationRequest<OID4VP>> {
        match (
            self.client_id.take(),
            self.request.take(),
            self.request_uri.take(),
            self.is_empty(),
        ) {
            (None, _, _, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), Some(request), None, true) => {
                Ok(AuthorizationRequest::<OID4VP>::ByValue { client_id, request })
            }
            (Some(client_id), None, Some(request_uri), true) => {
                Ok(AuthorizationRequest::<OID4VP>::ByReference { client_id, request_uri })
            }
            (Some(client_id), None, None, false) => {
                let extension = OID4VPAuthorizationRequestParameters {
                    presentation_definition: self
                        .presentation_definition
                        .take()
                        .ok_or_else(|| anyhow!("presentation_definition parameter is required."))?,
                    client_id_scheme: self.client_id_scheme.take(),
                    scope: self.scope.take(),
                    response_mode: self.response_mode.take(),
                    nonce: self
                        .nonce
                        .take()
                        .ok_or_else(|| anyhow!("nonce parameter is required."))?,
                    client_metadata: self.client_metadata.take(),
                };

                Ok(AuthorizationRequest::<OID4VP>::Object(Box::new(
                    AuthorizationRequestObject::<OID4VP> {
                        rfc7519_claims: self.rfc7519_claims,
                        client_id,
                        response_type: Default::default(),
                        redirect_uri: self
                            .redirect_uri
                            .take()
                            .ok_or_else(|| anyhow!("redirect_uri parameter is required."))?,
                        state: self.state.take(),
                        extension,
                    },
                )))
            }
            _ => Err(anyhow!(
                "one of either request_uri, request or other parameters should be set"
            )),
        }
    }
}
