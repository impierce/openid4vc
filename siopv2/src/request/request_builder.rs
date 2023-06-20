use crate::{
    builder_fn,
    claims::ClaimRequests,
    request::{AuthorizationRequest, RequestUrl, ResponseType},
    token::id_token::RFC7519Claims,
    ClientMetadata, Scope,
};
use anyhow::{anyhow, Result};
use is_empty::IsEmpty;
use oid4vp::PresentationDefinition;

#[derive(Default, IsEmpty)]
pub struct RequestUrlBuilder {
    rfc7519_claims: RFC7519Claims,
    client_id: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    response_type: Option<ResponseType>,
    response_mode: Option<String>,
    scope: Option<Scope>,
    claims: Option<Result<ClaimRequests>>,
    presentation_definition: Option<PresentationDefinition>,
    redirect_uri: Option<String>,
    nonce: Option<String>,
    client_metadata: Option<ClientMetadata>,
    state: Option<String>,
}

impl RequestUrlBuilder {
    pub fn new() -> Self {
        RequestUrlBuilder::default()
    }

    pub fn build(mut self) -> Result<RequestUrl> {
        match (
            self.client_id.take(),
            self.request.take(),
            self.request_uri.take(),
            self.is_empty(),
        ) {
            (None, _, _, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), Some(request), None, true) => Ok(RequestUrl::RequestObject { client_id, request }),
            (Some(client_id), None, Some(request_uri), true) => Ok(RequestUrl::RequestUri { client_id, request_uri }),
            (Some(client_id), None, None, false) => Ok(RequestUrl::Request(Box::new(AuthorizationRequest {
                rfc7519_claims: self.rfc7519_claims,
                client_id,
                response_type: self
                    .response_type
                    .take()
                    .ok_or_else(|| anyhow!("response_type parameter is required."))?,
                response_mode: self.response_mode.take(),
                scope: self
                    .scope
                    .take()
                    .ok_or_else(|| anyhow!("scope parameter is required."))?,
                claims: self.claims.take().transpose()?,
                presentation_definition: self.presentation_definition.take(),
                redirect_uri: self
                    .redirect_uri
                    .take()
                    .ok_or_else(|| anyhow!("redirect_uri parameter is required."))?,
                nonce: self
                    .nonce
                    .take()
                    .ok_or_else(|| anyhow!("nonce parameter is required."))?,
                client_metadata: self.client_metadata.take(),
                state: self.state.take(),
            }))),
            _ => Err(anyhow!(
                "one of either request_uri, request or other parameters should be set"
            )),
        }
    }

    pub fn claims<T: TryInto<ClaimRequests>>(mut self, value: T) -> Self {
        self.claims = Some(value.try_into().map_err(|_| anyhow!("failed to convert")));
        self
    }

    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(request_uri, String);
    builder_fn!(response_type, ResponseType);
    builder_fn!(response_mode, String);
    builder_fn!(client_id, String);
    builder_fn!(scope, Scope);
    builder_fn!(presentation_definition, PresentationDefinition);
    builder_fn!(redirect_uri, String);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadata);
    builder_fn!(state, String);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{claims::IndividualClaimRequest, ClaimRequests, StandardClaimsRequests};

    #[test]
    fn test_valid_request_builder() {
        let request_url = RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:example:123".to_string())
            .scope(Scope::openid())
            .redirect_uri("https://example.com".to_string())
            .nonce("nonce".to_string())
            .claims(
                r#"{
                    "id_token": {
                        "name": null
                    }
                }"#,
            )
            .build()
            .unwrap();

        assert_eq!(
            request_url,
            RequestUrl::Request(Box::new(AuthorizationRequest {
                rfc7519_claims: RFC7519Claims::default(),
                response_type: ResponseType::IdToken,
                response_mode: None,
                client_id: "did:example:123".to_string(),
                scope: Scope::openid(),
                claims: Some(ClaimRequests {
                    id_token: Some(StandardClaimsRequests {
                        name: Some(IndividualClaimRequest::Null),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                presentation_definition: None,
                redirect_uri: "https://example.com".to_string(),
                nonce: "nonce".to_string(),
                client_metadata: None,
                state: None,
            }))
        );
    }

    #[test]
    fn test_invalid_request_builder() {
        // A request builder with a `request_uri` parameter should fail to build.
        assert!(RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:example:123".to_string())
            .scope(Scope::openid())
            .redirect_uri("https://example.com".to_string())
            .nonce("nonce".to_string())
            .request_uri("https://example.com/request_uri".to_string())
            .build()
            .is_err());

        // A request builder without an invalid claim request should fail to build.
        assert!(RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:example:123".to_string())
            .scope(Scope::openid())
            .redirect_uri("https://example.com".to_string())
            .nonce("nonce".to_string())
            .claims(
                r#"{
                    "id_token": {
                        "name": "invalid"
                    }
                }"#,
            )
            .build()
            .is_err());
    }

    #[test]
    fn test_valid_request_uri_builder() {
        let request_url = RequestUrl::builder()
            .client_id("did:example:123".to_string())
            .request_uri("https://example.com/request_uri".to_string())
            .build()
            .unwrap();

        assert_eq!(
            request_url,
            RequestUrl::RequestUri {
                client_id: "did:example:123".to_string(),
                request_uri: "https://example.com/request_uri".to_string()
            }
        );
    }
}
