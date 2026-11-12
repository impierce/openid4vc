use crate::{
    JsonObject, RFC7519Claims,
    openid4vc_extension::{Extension, Generic, OpenID4VC, RequestHandle},
    utils::form_urlencoded::form_urlencoded_to_json_object,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;

// TODO: refactor this
// A `RedirectOrResponseUri` is either a `redirect_uri` or a `response_uri`. `redirect_uri`s are used in `siopv2` flows, while `response_uri`s are used in `openid4vp` flows.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RedirectOrResponseUri {
    RedirectUri(url::Url),
    ResponseUri(url::Url),
}

impl RedirectOrResponseUri {
    pub fn uri(&self) -> &url::Url {
        match self {
            RedirectOrResponseUri::RedirectUri(redirect_uri) => redirect_uri,
            RedirectOrResponseUri::ResponseUri(response_uri) => response_uri,
        }
    }
}

/// A `Body` is a set of claims that are sent by a client to a provider. It can be `ByValue`, `ByReference`, or an `Object`.
pub trait Body: Serialize + std::fmt::Debug {
    fn client_id(&self) -> &String;
}

/// An `Object` is a set of claims that are sent by a client to a provider. On top of some generic claims, it also
/// contains a set of claims specific to an [`Extension`].
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Object<E: Extension = Generic> {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub client_id: String,
    #[serde(flatten)]
    pub uri: RedirectOrResponseUri,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(flatten)]
    pub extension: <E::RequestHandle as RequestHandle>::Parameters,
}

impl<E: Extension> Object<E> {
    /// Converts a [`Object`] with a [`Generic`] [`Extension`] to a [`Object`] with a specific [`Extension`].
    fn from_generic(original: &Object<Generic>) -> anyhow::Result<Self> {
        Ok(Object {
            rfc7519_claims: original.rfc7519_claims.clone(),
            client_id: original.client_id.clone(),
            uri: original.uri.clone(),
            state: original.state.clone(),
            extension: serde_json::from_value(original.extension.clone())?,
        })
    }
}

impl<E: Extension> std::str::FromStr for Object<E> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (_, map) = query_parameters(s)?;
        let authorization_request: Object<E> = serde_json::from_value(serde_json::Value::Object(map))?;
        Ok(authorization_request)
    }
}

impl<E: Extension> Body for Object<E> {
    fn client_id(&self) -> &String {
        &self.client_id
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ByReference {
    pub client_id: String,
    pub request_uri: url::Url,
}

impl Body for ByReference {
    fn client_id(&self) -> &String {
        &self.client_id
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ByValue {
    pub client_id: String,
    pub request: String,
}
impl Body for ByValue {
    fn client_id(&self) -> &String {
        &self.client_id
    }
}

/// A [`AuthorizationRequest`] is a request that is sent by a client to a provider. It contains a set of claims in the
/// form of a [`Body`] which can be [`ByValue`], [`ByReference`], or an [`Object`].
/// NOTE: the final details between the Authorization Request as defined in OID4VCI and the one in OID4VP may differ.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationRequest<B: Body> {
    #[serde(skip)]
    pub custom_url_scheme: String,
    #[serde(flatten)]
    pub body: B,
}

impl<E: Extension + OpenID4VC> AuthorizationRequest<Object<E>> {
    /// Converts a [`AuthorizationRequest`] with a [`Generic`] [`Extension`] to a [`AuthorizationRequest`] with a specific [`Extension`].
    pub fn from_generic(
        original: &AuthorizationRequest<Object<Generic>>,
    ) -> anyhow::Result<AuthorizationRequest<Object<E>>> {
        Ok(AuthorizationRequest {
            custom_url_scheme: original.custom_url_scheme.clone(),
            body: Object::from_generic(&original.body)?,
        })
    }
}

impl<E: Extension> AuthorizationRequest<Object<E>> {
    /// Returns a [`AuthorizationRequest`]'s builder.
    pub fn builder() -> <E::RequestHandle as RequestHandle>::Builder {
        <E::RequestHandle as RequestHandle>::Builder::default()
    }
}

/// Parses the query of an Authorization Request URL into its scheme and a JSON object of its parameters. Every
/// parameter is a string, except those whose value is a JSON object or array: the JSON-encoded parameters such as
/// `claims`, `client_metadata` or `dcql_query`. A value such as `state=42` stays the string `"42"`.
fn query_parameters(s: &str) -> anyhow::Result<(String, JsonObject)> {
    let url = url::Url::parse(s)?;
    let query = url.query().ok_or_else(|| anyhow::anyhow!("No query found."))?;
    Ok((url.scheme().to_string(), form_urlencoded_to_json_object(query)?))
}

impl<B: Body + DeserializeOwned> std::str::FromStr for AuthorizationRequest<B> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, map) = query_parameters(s)?;
        tracing::debug!(%scheme, "Parsing AuthorizationRequest from URL string");
        let mut authorization_request: AuthorizationRequest<B> =
            serde_json::from_value(serde_json::Value::Object(map))?;
        authorization_request.custom_url_scheme = scheme;
        Ok(authorization_request)
    }
}

/// Prints the [`AuthorizationRequest`] as `<scheme>://?<query>`. Every value becomes a string: objects and arrays as
/// JSON, numbers and booleans as their JSON text (`exp=1700000000`); `null` values are left out.
impl<B: Body> std::fmt::Display for AuthorizationRequest<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map: JsonObject = json!(self)
            .as_object()
            .ok_or(std::fmt::Error)?
            .iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::Null => None,
                serde_json::Value::String(_) => Some((k.to_owned(), v.to_owned())),
                _ => Some((k.to_owned(), serde_json::Value::String(serde_json::to_string(v).ok()?))),
            })
            .collect();

        let encoded = serde_urlencoded::to_string(map).map_err(|_| std::fmt::Error)?;
        write!(f, "{}://?{}", self.custom_url_scheme, encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test() {
        let authorization_request = AuthorizationRequest::<Object> {
            custom_url_scheme: "test".to_string(),
            body: Object {
                rfc7519_claims: Default::default(),
                client_id: "did:example:123".to_string(),
                uri: RedirectOrResponseUri::RedirectUri("https://www.example.com".parse().unwrap()),
                state: Some("state".to_string()),
                extension: json!({
                    "response_mode": "direct_post",
                    "nonce": "nonce",
                    "claims": {
                        "id_token": {
                            "email": {
                                "essential": true
                            }
                        }
                    }
                }),
            },
        };

        // Convert the authorization request to a form urlencoded string.
        let form_urlencoded = authorization_request.to_string();

        // Convert the form urlencoded string back to a authorization request.
        assert_eq!(
            AuthorizationRequest::<Object>::from_str(&form_urlencoded).unwrap(),
            authorization_request
        );
    }

    #[test]
    fn test_url_round_trip_keeps_numeric_claims() {
        let authorization_request = AuthorizationRequest::<Object> {
            custom_url_scheme: "openid".to_string(),
            body: Object {
                rfc7519_claims: RFC7519Claims {
                    exp: Some(1700000000),
                    iat: Some(1600000000),
                    ..Default::default()
                },
                client_id: "did:example:123".to_string(),
                uri: RedirectOrResponseUri::RedirectUri("https://www.example.com".parse().unwrap()),
                state: None,
                extension: json!({"nonce": "nonce"}),
            },
        };

        let url = authorization_request.to_string();
        assert!(url.contains("exp=1700000000"), "{url}");
        assert_eq!(
            AuthorizationRequest::<Object>::from_str(&url).unwrap(),
            authorization_request
        );
    }

    #[test]
    fn test_from_str_keeps_numeric_looking_strings() {
        let authorization_request = AuthorizationRequest::<Object>::from_str(
            "openid://?client_id=123&redirect_uri=https%3A%2F%2Fexample.com&state=42&nonce=true",
        )
        .unwrap();

        assert_eq!(authorization_request.body.client_id, "123");
        assert_eq!(authorization_request.body.state.as_deref(), Some("42"));
        assert_eq!(authorization_request.body.extension, json!({"nonce": "true"}));
    }
}
