use crate::{
    claims::{ClaimRequests, IndividualClaimRequest},
    request::{RequestUrl, ResponseType, SiopRequest},
    Registration, Scope,
};
use anyhow::{anyhow, Result};
use is_empty::IsEmpty;

#[derive(Default, IsEmpty)]
pub struct RequestUrlBuilder {
    request_uri: Option<String>,
    response_type: Option<ResponseType>,
    response_mode: Option<String>,
    client_id: Option<String>,
    scope: Option<Scope>,
    claims: Option<ClaimRequests>,
    redirect_uri: Option<String>,
    nonce: Option<String>,
    registration: Option<Registration>,
    iss: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    nbf: Option<i64>,
    jti: Option<String>,
    state: Option<String>,
}

macro_rules! builder_fn {
    ($name:ident, $ty:ty) => {
        pub fn $name(mut self, value: $ty) -> Self {
            self.$name = Some(value);
            self
        }
    };
}

impl RequestUrlBuilder {
    pub fn new() -> Self {
        RequestUrlBuilder::default()
    }

    pub fn build(&mut self) -> Result<RequestUrl> {
        let request_uri = self.request_uri.take();
        match (request_uri, self.is_empty()) {
            (Some(request_uri), true) => Ok(RequestUrl::RequestUri { request_uri }),
            (None, _) => {
                let request = SiopRequest {
                    response_type: self
                        .response_type
                        .clone()
                        .ok_or(anyhow!("response_type parameter is required."))?,
                    response_mode: self.response_mode.clone(),
                    client_id: self
                        .client_id
                        .clone()
                        .ok_or(anyhow!("client_id parameter is required."))?,
                    scope: self.scope.clone().ok_or(anyhow!("scope parameter is required."))?,
                    claims: self.claims.clone(),
                    redirect_uri: self
                        .redirect_uri
                        .clone()
                        .ok_or(anyhow!("redirect_uri parameter is required."))?,
                    nonce: self.nonce.clone().ok_or(anyhow!("nonce parameter is required."))?,
                    registration: self.registration.clone(),
                    iss: self.iss.clone(),
                    iat: self.iat,
                    exp: self.exp,
                    nbf: self.nbf,
                    jti: self.jti.clone(),
                    state: self.state.clone(),
                };
                Ok(RequestUrl::Request(Box::new(request)))
            }
            _ => Err(anyhow!(
                "request_uri and other parameters cannot be set at the same time."
            )),
        }
    }

    pub fn claims<T: TryInto<ClaimRequests>>(mut self, value: T) -> Self
    where
        <T as TryInto<ClaimRequests>>::Error: std::fmt::Debug,
    {
        let value = value.try_into().unwrap();
        self.claims = Some(value);
        self
    }

    builder_fn!(request_uri, String);
    builder_fn!(response_type, ResponseType);
    builder_fn!(response_mode, String);
    builder_fn!(client_id, String);
    builder_fn!(scope, Scope);
    // builder_fn!(claims, ClaimRequests);
    builder_fn!(redirect_uri, String);
    builder_fn!(nonce, String);
    builder_fn!(registration, Registration);
    builder_fn!(iss, String);
    builder_fn!(iat, i64);
    builder_fn!(exp, i64);
    builder_fn!(nbf, i64);
    builder_fn!(jti, String);
    builder_fn!(state, String);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request_builder() {
        let request_url = RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:example:123".to_string())
            .scope(Scope::openid())
            .redirect_uri("https://example.com".to_string())
            .nonce("nonce".to_string())
            .build()
            .unwrap();

        assert_eq!(
            request_url,
            RequestUrl::Request(Box::new(SiopRequest {
                response_type: ResponseType::IdToken,
                response_mode: None,
                client_id: "did:example:123".to_string(),
                scope: Scope::openid(),
                claims: None,
                redirect_uri: "https://example.com".to_string(),
                nonce: "nonce".to_string(),
                registration: None,
                iss: None,
                iat: None,
                exp: None,
                nbf: None,
                jti: None,
                state: None,
            }))
        );
    }

    #[test]
    fn test_invalid_request_builder() {
        // A request builder with a `request_uri` parameter should fail to build.
        let request_url = RequestUrl::builder()
            .response_type(ResponseType::IdToken)
            .client_id("did:example:123".to_string())
            .scope(Scope::openid())
            .redirect_uri("https://example.com".to_string())
            .nonce("nonce".to_string())
            .request_uri("https://example.com/request_uri".to_string())
            .build();
        assert!(request_url.is_err());
    }

    #[test]
    fn test_valid_request_uri_builder() {
        let request_url = RequestUrl::builder()
            .request_uri("https://example.com/request_uri".to_string())
            .build()
            .unwrap();

        assert_eq!(
            request_url,
            RequestUrl::RequestUri {
                request_uri: "https://example.com/request_uri".to_string()
            }
        );
    }
}
