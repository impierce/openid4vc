use crate::{provider::Subject, relying_party::Validator};
use anyhow::{anyhow, Result};
use getset::Getters;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::str::FromStr;

#[derive(Deserialize, Debug, PartialEq)]
#[serde(untagged, deny_unknown_fields)]
pub enum RequestUrl {
    Request(Box<SiopRequest>),
    // TODO: Add client_id parameter.
    RequestUri { request_uri: String },
}

impl RequestUrl {
    pub async fn try_into<S>(self, subject: &S) -> Result<SiopRequest>
    where
        S: Subject + Validator,
    {
        match self {
            RequestUrl::Request(request) => Ok(*request),
            RequestUrl::RequestUri { request_uri } => {
                let client = reqwest::Client::new();
                let builder = client.get(request_uri);
                let request_value = builder.send().await?.text().await?;
                Ok(subject.decode(request_value).await?)
            }
        }
    }
}

impl FromStr for RequestUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = url::Url::parse(s)?;
        let decoded: Map<String, Value> =
            url::form_urlencoded::parse(url.query().ok_or(anyhow!("No query found."))?.as_bytes())
                .map(|(k, v)| (k.into(), serde_json::from_str::<Value>(&v).unwrap_or_else(|_| v.into())))
                .collect();
        let request: RequestUrl = serde_json::from_value(decoded.into())?;
        Ok(request)
    }
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseType {
    IdToken,
}

/// [`SiopRequest`] is a request from a [crate::relying_party::RelyingParty] (RP) to a [crate::provider::Provider] (SIOP).
#[allow(dead_code)]
#[derive(Deserialize, Debug, Getters, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SiopRequest {
    response_type: ResponseType,
    response_mode: Option<String>,
    #[getset(get = "pub")]
    client_id: String,
    scope: String,
    claims: Option<Map<String, Value>>,
    // MUST be present in cross-device SIOP request
    #[getset(get = "pub")]
    redirect_uri: Option<String>,
    #[getset(get = "pub")]
    nonce: String,
    #[getset(get = "pub")]
    registration: Option<Registration>,
    iss: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
    nbf: Option<i64>,
    jti: Option<String>,
    #[getset(get = "pub")]
    state: Option<String>,
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

#[derive(Deserialize, Getters, Debug, PartialEq)]
pub struct Registration {
    #[getset(get = "pub")]
    subject_syntax_types_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_request_uri() {
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url =
            RequestUrl::from_str("https://example.com?request_uri=https://example.com/request_uri").unwrap();
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
                %22id_token_signing_alg_values_supported%22%3A%5B%22ES256%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();
        assert_eq!(
            request_url,
            RequestUrl::Request(Box::new(SiopRequest {
                response_type: ResponseType::IdToken,
                response_mode: Some("post".to_owned()),
                client_id: "did:example:\
                            EiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA"
                    .to_owned(),
                scope: "openid".to_owned(),
                claims: None,
                redirect_uri: Some("https://client.example.org/cb".to_owned()),
                nonce: "n-0S6_WzA2Mj".to_owned(),
                registration: Some(Registration {
                    subject_syntax_types_supported: Some(vec!["did:mock".to_owned()]),
                    id_token_signing_alg_values_supported: Some(vec!["ES256".to_owned()]),
                }),
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
                %22id_token_signing_alg_values_supported%22%3A%5B%22ES256%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
                &request_uri=https://example.com/request_uri\
            ",
        );
        dbg!(&request_url);
        assert!(request_url.is_err())
    }

    #[test]
    fn test_invalid_request_uri() {
        // A form urlencoded string with a `request_uri` parameter should deserialize into the `RequestUrl::RequestUri` variant.
        let request_url =
            RequestUrl::from_str("https://example.com?request_uri=https://example.com/request_uri&scope=openid");
        assert!(request_url.is_err(),);
    }
}
