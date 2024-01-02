use crate::{siopv2::SIOPv2, ClaimRequests, StandardClaimsRequests};
use anyhow::{anyhow, Result};
use is_empty::IsEmpty;
use oid4vc_core::authorization_request::Object;
use oid4vc_core::builder_fn;
use oid4vc_core::{
    authorization_request::AuthorizationRequest, client_metadata::ClientMetadata, scope::Scope, RFC7519Claims,
    SubjectSyntaxType,
};
use serde::{Deserialize, Serialize};

/// [`AuthorizationRequest`] claims specific to [`SIOPv2`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(tag = "response_type", rename = "id_token")]
pub struct AuthorizationRequestParameters {
    // TODO: make generic Scope and add it to `AuthorizationRequest`.
    pub scope: Scope,
    pub response_mode: Option<String>,
    pub nonce: String,
    pub claims: Option<ClaimRequests>,
    // TODO: impl client_metadata_uri.
    pub client_metadata: Option<ClientMetadata>,
}

impl AuthorizationRequestParameters {
    pub fn is_cross_device_request(&self) -> bool {
        self.response_mode == Some("post".to_string())
    }

    pub fn subject_syntax_types_supported(&self) -> Option<&Vec<SubjectSyntaxType>> {
        self.client_metadata
            .as_ref()
            .and_then(|r| r.subject_syntax_types_supported().as_ref())
    }

    /// Returns the `id_token` claims from the `claims` parameter including those from the request's scope values.
    pub fn id_token_request_claims(&self) -> Option<StandardClaimsRequests> {
        self.claims
            .as_ref()
            .and_then(|claims| claims.id_token.clone())
            .map(|mut id_token_claims| {
                id_token_claims.merge((&self.scope).into());
                id_token_claims
            })
    }
}

#[derive(Debug, Default, IsEmpty)]
pub struct AuthorizationRequestBuilder {
    rfc7519_claims: RFC7519Claims,
    client_id: Option<String>,
    redirect_uri: Option<url::Url>,
    state: Option<String>,
    scope: Option<Scope>,
    response_mode: Option<String>,
    nonce: Option<String>,
    claims: Option<Result<ClaimRequests>>,
    client_metadata: Option<ClientMetadata>,
}

impl AuthorizationRequestBuilder {
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
    builder_fn!(response_mode, String);
    builder_fn!(client_id, String);
    builder_fn!(scope, Scope);
    builder_fn!(redirect_uri, url::Url);
    builder_fn!(nonce, String);
    builder_fn!(client_metadata, ClientMetadata);
    builder_fn!(state, String);

    pub fn build(mut self) -> Result<AuthorizationRequest<Object<SIOPv2>>> {
        match (self.client_id.take(), self.is_empty()) {
            (None, _) => Err(anyhow!("client_id parameter is required.")),
            (Some(client_id), false) => {
                let extension = AuthorizationRequestParameters {
                    scope: self
                        .scope
                        .take()
                        .ok_or_else(|| anyhow!("scope parameter is required."))?,
                    response_mode: self.response_mode.take(),
                    nonce: self
                        .nonce
                        .take()
                        .ok_or_else(|| anyhow!("nonce parameter is required."))?,
                    claims: self.claims.take().transpose()?,
                    client_metadata: self.client_metadata.take(),
                };

                Ok(AuthorizationRequest::<Object<SIOPv2>> {
                    body: Object::<SIOPv2> {
                        rfc7519_claims: self.rfc7519_claims,
                        client_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{claims::IndividualClaimRequest, ClaimRequests, StandardClaimsRequests};
    use std::str::FromStr;

    #[test]
    fn test_authorization_request_serde() {
        let request_url = AuthorizationRequest::<Object<SIOPv2>>::from_str(
            "\
                siopv2://idtoken?\
                    scope=openid\
                    &response_type=id_token\
                    &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                    &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                    &response_mode=direct_post\
                    &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                    %5B%22did%3Atest%22%5D%2C%0A%20%20%20%20\
                    %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                    &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();

        assert_eq!(
            AuthorizationRequest::<Object<SIOPv2>>::from_str(&AuthorizationRequest::<Object<SIOPv2>>::to_string(
                &request_url
            ))
            .unwrap(),
            request_url
        );
    }

    #[test]
    fn test_valid_request_builder() {
        let request_url = AuthorizationRequest::<Object<SIOPv2>>::builder()
            .client_id("did:example:123".to_string())
            .scope(Scope::openid())
            .redirect_uri("https://example.com".parse::<url::Url>().unwrap())
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
            AuthorizationRequest::<Object<SIOPv2>> {
                body: Object::<SIOPv2> {
                    rfc7519_claims: RFC7519Claims::default(),
                    client_id: "did:example:123".to_string(),
                    redirect_uri: "https://example.com".parse().unwrap(),
                    state: None,
                    extension: AuthorizationRequestParameters {
                        scope: Scope::openid(),
                        response_mode: None,
                        nonce: "nonce".to_string(),
                        claims: Some(ClaimRequests {
                            id_token: Some(StandardClaimsRequests {
                                name: Some(IndividualClaimRequest::Null),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        client_metadata: None,
                    },
                }
            }
        );
    }

    // #[test]
    // fn test_invalid_request_builder() {
    //     // A request builder with a `request_uri` parameter should fail to build.
    //     assert!(AuthorizationRequest::<Object<SIOPv2>>::builder()
    //         .client_id("did:example:123".to_string())
    //         .scope(Scope::openid())
    //         .redirect_uri("https://example.com".parse::<url::Url>().unwrap())
    //         .nonce("nonce".to_string())
    //         .build()
    //         .is_err());

    //     // A request builder without an invalid claim request should fail to build.
    //     assert!(AuthorizationRequest::<Object<SIOPv2>>::builder()
    //         .client_id("did:example:123".to_string())
    //         .scope(Scope::openid())
    //         .redirect_uri("https://example.com".parse::<url::Url>().unwrap())
    //         .nonce("nonce".to_string())
    //         .claims(
    //             r#"{
    //                 "id_token": {
    //                     "name": "invalid"
    //                 }
    //             }"#,
    //         )
    //         .build()
    //         .is_err());
    // }

    // #[test]
    // fn test_valid_request_uri_builder() {
    //     let request_url = AuthorizationRequest::<ByReference>::builder()
    //         .client_id("did:example:123".to_string())
    //         .request_uri("https://example.com/request_uri".parse::<url::Url>().unwrap())
    //         .build()
    //         .unwrap();

    //     assert_eq!(
    //         request_url,
    //         AuthorizationRequest::<SIOPv2>::ByReference {
    //             client_id: "did:example:123".to_string(),
    //             request_uri: "https://example.com/request_uri".parse().unwrap()
    //         }
    //     );
    // }
}
