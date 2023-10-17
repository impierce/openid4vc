use crate::oid4vp::OID4VP;
use anyhow::{anyhow, Result};
use dif_presentation_exchange::PresentationDefinition;
use is_empty::IsEmpty;
use oid4vc_core::authorization_request::Object;
use oid4vc_core::builder_fn;
use oid4vc_core::{
    authorization_request::AuthorizationRequest, client_metadata::ClientMetadata, scope::Scope, RFC7519Claims,
};
use serde::{Deserialize, Serialize};

/// [`AuthorizationRequest`] claims specific to [`OID4VP`].
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationRequestParameters {
    pub presentation_definition: PresentationDefinition,
    pub client_id_scheme: Option<String>,
    pub response_mode: Option<String>,
    pub scope: Option<Scope>,
    pub nonce: String,
    // TODO: impl client_metadata_uri.
    pub client_metadata: Option<ClientMetadata>,
}

#[derive(Debug, Default, IsEmpty)]
pub struct AuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    presentation_definition: Option<PresentationDefinition>,
    client_id_scheme: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<url::Url>,
    state: Option<String>,
    scope: Option<Scope>,
    response_mode: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadata>,
}

impl AuthorizationRequestBuilder {
    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(response_mode, String);
    builder_fn!(client_id, String);
    builder_fn!(scope, Scope);
    builder_fn!(redirect_uri, url::Url);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadata);
    builder_fn!(state, String);
    builder_fn!(presentation_definition, PresentationDefinition);

    pub fn build(mut self) -> Result<AuthorizationRequest<Object<OID4VP>>> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
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

                Ok(AuthorizationRequest::<Object<OID4VP>> {
                    body: Object::<OID4VP> {
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
                })
            }
            _ => Err(anyhow!(
                "one of either request_uri, request or other parameters should be set"
            )),
        }
    }
}
