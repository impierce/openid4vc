use crate::{
    openid4vc_extension::{Extension, Generic, OpenID4VC, RequestHandle},
    JsonObject, JsonValue, RFC7519Claims,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

pub trait Body: Serialize + std::fmt::Debug {
    fn client_id(&self) -> &String;
    fn response_type(&self) -> Option<String>;
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Object<E: Extension = Generic> {
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub response_type: <E::RequestHandle as RequestHandle>::ResponseType,
    pub client_id: String,
    pub redirect_uri: url::Url,
    pub state: Option<String>,
    #[serde(flatten)]
    pub extension: <E::RequestHandle as RequestHandle>::Parameters,
}

impl<E: Extension> Object<E> {
    fn from_generic(original: Object<Generic>) -> anyhow::Result<Self> {
        Ok(Object {
            rfc7519_claims: original.rfc7519_claims,
            // TODO: fix error message
            response_type: original.response_type.parse().map_err(|_| anyhow::anyhow!(""))?,
            client_id: original.client_id,
            redirect_uri: original.redirect_uri,
            state: original.state,
            extension: serde_json::from_value(original.extension)?,
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
                JsonValue::String(s) => Some(Ok((k, serde_json::from_str(&s).unwrap_or(JsonValue::String(s))))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
        let authorization_request: Object<E> = serde_json::from_value(JsonValue::Object(map))?;
        Ok(authorization_request)
    }
}

impl<E: Extension> Body for Object<E> {
    fn client_id(&self) -> &String {
        &self.client_id
    }
    fn response_type(&self) -> Option<String> {
        Some(self.response_type.to_string())
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
    fn response_type(&self) -> Option<String> {
        None
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
    fn response_type(&self) -> Option<String> {
        None
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationRequest<B: Body> {
    #[serde(flatten)]
    pub body: B,
}

impl<E: Extension + OpenID4VC> AuthorizationRequest<Object<E>> {
    pub fn from_generic(
        original: AuthorizationRequest<Object<Generic>>,
    ) -> anyhow::Result<AuthorizationRequest<Object<E>>> {
        Ok(AuthorizationRequest {
            body: Object::from_generic(original.body)?,
        })
    }
}

impl<E: Extension> AuthorizationRequest<Object<E>> {
    pub fn builder() -> <E::RequestHandle as RequestHandle>::Builder {
        <E::RequestHandle as RequestHandle>::Builder::default()
    }
}

/// In order to convert a string to a [`RequestUrl`], we need to try to parse each value as a JSON object. This way we
/// can catch any non-primitive types. If the value is not a JSON object or an Array, we just leave it as a string.
impl<B: Body + DeserializeOwned> std::str::FromStr for AuthorizationRequest<B> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let query = url.query().ok_or_else(|| anyhow::anyhow!("No query found."))?;
        let map = serde_urlencoded::from_str::<JsonObject>(query)?
            .into_iter()
            .filter_map(|(k, v)| match v {
                JsonValue::String(s) => Some(Ok((k, serde_json::from_str(&s).unwrap_or(JsonValue::String(s))))),
                _ => None,
            })
            .collect::<Result<_, anyhow::Error>>()?;
        let authorization_request: AuthorizationRequest<B> = serde_json::from_value(JsonValue::Object(map))?;
        Ok(authorization_request)
    }
}

/// In order to convert a [`RequestUrl`] to a string, we need to convert all the values to strings. This is because
/// `serde_urlencoded` does not support serializing non-primitive types.
// TODO: Find a way to dynamically generate the `siopv2://idtoken?` part of the URL. This will require some refactoring
// for the `RequestUrl` enum.
impl<B: Body> std::fmt::Display for AuthorizationRequest<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let map: JsonObject = json!(self)
            .as_object()
            .ok_or(std::fmt::Error)?
            .iter()
            .filter_map(|(k, v)| match v {
                JsonValue::Object(_) | JsonValue::Array(_) => {
                    Some((k.to_owned(), JsonValue::String(serde_json::to_string(v).ok()?)))
                }
                JsonValue::String(_) => Some((k.to_owned(), v.to_owned())),
                _ => None,
            })
            .collect();

        let encoded = serde_urlencoded::to_string(map).map_err(|_| std::fmt::Error)?;
        write!(f, "siopv2://idtoken?{}", encoded)
    }
}
