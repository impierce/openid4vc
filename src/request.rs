use derive_more::Display;
use std::str::FromStr;

use crate::{Registration, RequestUrlBuilder};
use anyhow::{anyhow, Result};
use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Deserialize, Debug, PartialEq, Clone, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum RequestUrl {
    Request(Box<SiopRequest>),
    // TODO: Add client_id parameter.
    RequestUri { request_uri: String },
}

impl FromStr for RequestUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let query = url.query().ok_or(anyhow!("No query found."))?;
        let request: RequestUrl = serde_urlencoded::from_str(query)?;
        Ok(request)
    }
}

impl std::fmt::Display for RequestUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = serde_urlencoded::to_string(self).unwrap();
        dbg!(&encoded);
        write!(f, "siopv2://idtoken?{encoded}")
    }
}

impl RequestUrl {
    pub fn builder() -> RequestUrlBuilder {
        RequestUrlBuilder::new()
    }
}

#[derive(Deserialize, Debug, PartialEq, Clone, Serialize, Default, Display)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    #[default]
    #[display(fmt = "id_token")]
    IdToken,
}

/// [`SiopRequest`] is a request from a [crate::relying_party::RelyingParty] (RP) to a [crate::provider::Provider] (SIOP).
#[allow(dead_code)]
#[derive(Debug, Getters, PartialEq, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiopRequest {
    pub(crate) response_type: ResponseType,
    pub(crate) response_mode: Option<String>,
    #[getset(get = "pub")]
    pub(crate) client_id: String,
    pub(crate) scope: String,
    pub(crate) claims: Option<Map<String, Value>>,
    #[getset(get = "pub")]
    pub(crate) redirect_uri: String,
    #[getset(get = "pub")]
    pub(crate) nonce: String,
    #[getset(get = "pub")]
    pub(crate) registration: Option<Registration>,
    pub(crate) iss: Option<String>,
    pub(crate) iat: Option<i64>,
    pub(crate) exp: Option<i64>,
    pub(crate) nbf: Option<i64>,
    pub(crate) jti: Option<String>,
    #[getset(get = "pub")]
    pub(crate) state: Option<String>,
}

// TODO: implement an creational pattern for SiopRequest.
impl SiopRequest {
    pub fn is_cross_device_request(&self) -> bool {
        self.response_mode == Some("post".to_owned())
    }

    pub fn subject_syntax_types_supported(&self) -> Option<&Vec<String>> {
        self.registration
            .as_ref()
            .and_then(|r| r.subject_syntax_types_supported().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();

        assert_eq!(
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap(),
            request_url
        );
    }

    #[test]
    fn test_valid_request_uri() {
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url = RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri").unwrap();
        assert_eq!(
            request_url,
            RequestUrl::RequestUri {
                request_uri: "https://example.com/request_uri".to_owned()
            }
        );
    }

    #[test]
    fn test_valid_request() {
        // A form urlencoded string without a `request_uri` parameter should deserialize into the `RequestUrl::Request` variant.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();
        assert_eq!(
            request_url.clone(),
            RequestUrl::Request(Box::new(SiopRequest {
                response_type: ResponseType::IdToken,
                response_mode: Some("post".to_owned()),
                client_id: "did:example:\
                            EiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA"
                    .to_owned(),
                scope: "openid".to_owned(),
                claims: None,
                redirect_uri: "https://client.example.org/cb".to_owned(),
                nonce: "n-0S6_WzA2Mj".to_owned(),
                registration: Some(Registration {
                    subject_syntax_types_supported: Some(vec!["did:mock".to_owned()]),
                    id_token_signing_alg_values_supported: Some(vec!["EdDSA".to_owned()]),
                }),
                iss: None,
                iat: None,
                exp: None,
                nbf: None,
                jti: None,
                state: None,
            }))
        );

        assert_eq!(
            request_url,
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap()
        );
    }

    #[test]
    fn test_invalid_request() {
        // A form urlencoded string with an otherwise valide request is invalid when also the `request_uri` parameter is
        // present.
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
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
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url =
            RequestUrl::from_str("siopv2://idtoken?request_uri=https://example.com/request_uri&scope=openid");
        assert!(request_url.is_err(),);
    }
}
