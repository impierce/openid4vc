use crate::{
    openid4vc_extension::{Extension, Generic, OpenID4VC, RequestHandle},
    JsonObject, RFC7519Claims,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

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
    pub redirect_uri: url::Url,
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
            redirect_uri: original.redirect_uri.clone(),
            state: original.state.clone(),
            extension: serde_json::from_value(original.extension.clone())?,
        })
    }
}

impl<E: Extension> std::str::FromStr for Object<E> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let query = url.query().ok_or_else(|| anyhow::anyhow!("No query found."))?;
        let map = serde_urlencoded::from_str::<JsonObject>(query)?
            .into_iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::String(s) => Some(Ok((
                    k,
                    serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)),
                ))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
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

/// In order to convert a string to a [`AuthorizationRequest`], we need to try to parse each value as a JSON object. This way we
/// can catch any non-primitive types. If the value is not a JSON object or an Array, we just leave it as a string.
impl<B: Body + DeserializeOwned> std::str::FromStr for AuthorizationRequest<B> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let query = url.query().ok_or_else(|| anyhow::anyhow!("No query found."))?;
        let map = serde_urlencoded::from_str::<JsonObject>(query)?
            .into_iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::String(s) => Some(Ok((
                    k,
                    serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)),
                ))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
        let mut authorization_request: AuthorizationRequest<B> =
            serde_json::from_value(serde_json::Value::Object(map))?;
        authorization_request.custom_url_scheme = url.scheme().to_string();
        Ok(authorization_request)
    }
}

/// In order to convert a [`AuthorizationRequest`] to a string, we need to convert all the values to strings. This is because
/// `serde_urlencoded` does not support serializing non-primitive types.
impl<B: Body> std::fmt::Display for AuthorizationRequest<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map: JsonObject = json!(self)
            .as_object()
            .ok_or(std::fmt::Error)?
            .iter()
            .filter_map(|(k, v)| match v {
                serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                    Some((k.to_owned(), serde_json::Value::String(serde_json::to_string(v).ok()?)))
                }
                serde_json::Value::String(_) => Some((k.to_owned(), v.to_owned())),
                _ => None,
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
                redirect_uri: "https://www.example.com".parse().unwrap(),
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
}
