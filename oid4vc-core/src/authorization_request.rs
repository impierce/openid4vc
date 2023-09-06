use crate::{Extension, JsonObject, JsonValue, RFC7519Claims};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(untagged)]
pub enum AuthorizationRequest<E: Extension> {
    ByReference { client_id: String, request_uri: url::Url },
    ByValue { client_id: String, request: String },
    Object(Box<AuthorizationRequestObject<E>>),
}

impl<E: Extension> TryInto<AuthorizationRequestObject<E>> for AuthorizationRequest<E> {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<AuthorizationRequestObject<E>, Self::Error> {
        match self {
            AuthorizationRequest::ByReference { .. } => Err(anyhow::anyhow!("Request is a request URI.")),
            AuthorizationRequest::ByValue { .. } => Err(anyhow::anyhow!("Request is a request object.")),
            AuthorizationRequest::Object(authorization_request_object) => Ok(*authorization_request_object),
        }
    }
}

impl<E: Extension> AuthorizationRequest<E> {
    pub fn builder() -> E::AuthorizationRequestBuilder {
        E::AuthorizationRequestBuilder::default()
    }
}

/// In order to convert a string to a [`RequestUrl`], we need to try to parse each value as a JSON object. This way we
/// can catch any non-primitive types. If the value is not a JSON object or an Array, we just leave it as a string.
impl<E: Extension + DeserializeOwned> std::str::FromStr for AuthorizationRequest<E> {
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
        let request: AuthorizationRequest<E> = serde_json::from_value(JsonValue::Object(map))?;
        Ok(request)
    }
}

/// In order to convert a [`RequestUrl`] to a string, we need to convert all the values to strings. This is because
/// `serde_urlencoded` does not support serializing non-primitive types.
// TODO: Find a way to dynamically generate the `siopv2://idtoken?` part of the URL. This will require some refactoring
// for the `RequestUrl` enum.
impl<E: Extension> std::fmt::Display for AuthorizationRequest<E> {
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

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationRequestObject<E: Extension> {
    // TODO: Move this outside of this struct.
    #[serde(flatten)]
    pub rfc7519_claims: RFC7519Claims,
    pub response_type: E::ResponseType,
    pub client_id: String,
    pub redirect_uri: url::Url,
    pub state: Option<String>,
    #[serde(flatten)]
    pub extension: E::AuthorizationRequest,
}
