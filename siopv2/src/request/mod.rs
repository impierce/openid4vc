use crate::token::id_token::RFC7519Claims;
use crate::SubjectSyntaxType;
use crate::{claims::ClaimRequests, ClientMetadata, RequestUrlBuilder, Scope, StandardClaimsRequests};
use anyhow::{anyhow, Result};
use derive_more::Display;
use getset::Getters;
use merge::Merge;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::convert::TryInto;
use std::str::FromStr;

pub mod request_builder;

/// As specified in the
/// [SIOPv2 specification](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-openid-provider-a)
/// [`RelyingParty`]'s can either send a request as a query parameter or as a request URI.
/// # Examples
///
/// ```
/// # use siopv2::RequestUrl;
/// # use std::str::FromStr;
///
/// // An example of a form-urlencoded request with only the `request_uri` parameter will be parsed as a
/// // `RequestUrl::RequestUri` variant.
/// let request_url = RequestUrl::from_str("siopv2://idtoken?client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA&request_uri=https://example.com/request_uri").unwrap();
/// assert_eq!(
///     request_url,
///     RequestUrl::RequestUri {
///         client_id: "did:example:EiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA".to_string(),
///         request_uri: "https://example.com/request_uri".to_string()
///     }
/// );
///
/// // An example of a form-urlencoded request that is parsed as a `RequestUrl::AuthorizationRequest` variant.
/// let request_url = RequestUrl::from_str(
///     "\
///         siopv2://idtoken?\
///             scope=openid\
///             &response_type=id_token\
///             &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
///             &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
///             &response_mode=post\
///             &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
///             %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
///             %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
///             &nonce=n-0S6_WzA2Mj\
///     ",
/// )
/// .unwrap();
/// assert!(match request_url {
///   RequestUrl::Request(_) => Ok(()),
///   RequestUrl::RequestUri { .. } => Err(()),
///   RequestUrl::RequestObject { .. } => Err(()),
/// }.is_ok());
/// ```
#[derive(Deserialize, Debug, PartialEq, Serialize, Clone)]
#[serde(untagged, deny_unknown_fields)]
pub enum RequestUrl {
    Request(Box<AuthorizationRequest>),
    RequestObject { client_id: String, request: String },
    RequestUri { client_id: String, request_uri: String },
}

impl RequestUrl {
    pub fn builder() -> RequestUrlBuilder {
        RequestUrlBuilder::new()
    }
}

impl TryInto<AuthorizationRequest> for RequestUrl {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<AuthorizationRequest, Self::Error> {
        match self {
            RequestUrl::Request(request) => Ok(*request),
            RequestUrl::RequestUri { .. } => Err(anyhow!("Request is a request URI.")),
            RequestUrl::RequestObject { .. } => Err(anyhow!("Request is a request object.")),
        }
    }
}

/// In order to convert a string to a [`RequestUrl`], we need to try to parse each value as a JSON object. This way we
/// can catch any non-primitive types. If the value is not a JSON object or an Array, we just leave it as a string.
impl FromStr for RequestUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let query = url.query().ok_or_else(|| anyhow!("No query found."))?;
        let map = serde_urlencoded::from_str::<Map<String, Value>>(query)?
            .into_iter()
            .filter_map(|(k, v)| match v {
                Value::String(s) => Some(Ok((k, serde_json::from_str(&s).unwrap_or(Value::String(s))))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
        let request: RequestUrl = serde_json::from_value(Value::Object(map))?;
        Ok(request)
    }
}

/// In order to convert a [`RequestUrl`] to a string, we need to convert all the values to strings. This is because
/// `serde_urlencoded` does not support serializing non-primitive types.
// TODO: Find a way to dynamically generate the `siopv2://idtoken?` part of the URL. This will require some refactoring
// for the `RequestUrl` enum.
impl std::fmt::Display for RequestUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map: Map<String, Value> = serde_json::to_value(self)
            .map_err(|_| std::fmt::Error)?
            .as_object()
            .ok_or(std::fmt::Error)?
            .iter()
            .filter_map(|(k, v)| match v {
                Value::Object(_) | Value::Array(_) => Some((k.clone(), Value::String(serde_json::to_string(v).ok()?))),
                Value::String(_) => Some((k.clone(), v.clone())),
                _ => None,
            })
            .collect();

        let encoded = serde_urlencoded::to_string(map).map_err(|_| std::fmt::Error)?;
        write!(f, "siopv2://idtoken?{}", encoded)
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone, Serialize, Default, Display)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    #[default]
    #[display(fmt = "id_token")]
    IdToken,
}

/// [`AuthorizationRequest`] is a request from a [crate::relying_party::RelyingParty] (RP) to a [crate::provider::Provider] (SIOP).
#[allow(dead_code)]
#[derive(Debug, Getters, PartialEq, Default, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    #[serde(flatten)]
    #[getset(get = "pub")]
    pub(super) rfc7519_claims: RFC7519Claims,
    pub(crate) response_type: ResponseType,
    pub(crate) response_mode: Option<String>,
    #[getset(get = "pub")]
    pub(crate) client_id: String,
    #[getset(get = "pub")]
    pub(crate) scope: Scope,
    #[getset(get = "pub")]
    pub(crate) claims: Option<ClaimRequests>,
    #[getset(get = "pub")]
    pub(crate) redirect_uri: String,
    #[getset(get = "pub")]
    pub(crate) nonce: String,
    #[getset(get = "pub")]
    pub(crate) client_metadata: Option<ClientMetadata>,
    #[getset(get = "pub")]
    pub(crate) state: Option<String>,
}

impl AuthorizationRequest {
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
        self.claims()
            .as_ref()
            .and_then(|claims| claims.id_token.clone())
            .map(|mut id_token_claims| {
                id_token_claims.merge(self.scope().into());
                id_token_claims
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::subject_syntax_type::DidMethod;

    use super::*;

    #[test]
    fn test_valid_request_uri() {
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url = RequestUrl::from_str("siopv2://idtoken?client_id=https%3A%2F%2Fclient.example.org%2Fcb&request_uri=https://example.com/request_uri").unwrap();
        assert_eq!(
            request_url,
            RequestUrl::RequestUri {
                client_id: "https://client.example.org/cb".to_string(),
                request_uri: "https://example.com/request_uri".to_string(),
            }
        );
    }

    #[test]
    fn test_valid_request() {
        // A form urlencoded string without a `request_uri` parameter should deserialize into the `RequestUrl::AuthorizationRequest` variant.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();
        assert_eq!(
            request_url.clone(),
            RequestUrl::Request(Box::new(AuthorizationRequest {
                rfc7519_claims: RFC7519Claims::default(),
                response_type: ResponseType::IdToken,
                response_mode: Some("post".to_string()),
                client_id: "did:example:\
                            EiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA"
                    .to_string(),
                scope: Scope::openid(),
                claims: None,
                redirect_uri: "https://client.example.org/cb".to_string(),
                nonce: "n-0S6_WzA2Mj".to_string(),
                client_metadata: Some(
                    ClientMetadata::default()
                        .with_subject_syntax_types_supported(vec![SubjectSyntaxType::Did(
                            DidMethod::from_str("did:mock").unwrap()
                        )])
                        .with_id_token_signing_alg_values_supported(vec!["EdDSA".to_string()]),
                ),
                state: None,
            }))
        );

        assert_eq!(
            request_url,
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap()
        );
    }

    #[test]
    fn test_valid_request_object() {
        // A form urlencoded string with a `request` parameter should deserialize into the `RequestUrl::RequestObject` variant.
        let request_url = RequestUrl::from_str(
            "siopv2://idtoken?client_id=https%3A%2F%2Fclient.example.org%2Fcb&request=eyJhb...lMGzw",
        )
        .unwrap();
        assert_eq!(
            request_url,
            RequestUrl::RequestObject {
                client_id: "https://client.example.org/cb".to_string(),
                request: "eyJhb...lMGzw".to_string()
            }
        );
    }

    #[test]
    fn test_invalid_request() {
        // A form urlencoded string with an otherwise valid request is invalid when the `request_uri` parameter is also
        // present.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
                &request_uri=https://example.com/request_uri\
            ",
        );
        assert!(request_url.is_err())
    }

    #[test]
    fn test_invalid_request_uri() {
        // A form urlencoded string with a `request_uri` should not have any other parameters.
        let request_url =
            RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri&scope=openid");
        assert!(request_url.is_err(),);
    }
}
