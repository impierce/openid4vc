use crate::{provider::Subject, relying_party::Validator};
use anyhow::{anyhow, Result};
use getset::Getters;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::str::FromStr;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
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
#[derive(Deserialize, Debug, Getters)]
pub struct SiopRequest {
    response_type: ResponseType,
    response_mode: Option<String>,
    #[getset(get = "pub")]
    client_id: String,
    request_uri: Option<String>,
    scope: String,
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
    #[getset(get = "pub")]
    state: Option<String>,
}

// TODO: implement an creational pattern for SiopRequest.
impl SiopRequest {
    pub fn is_cross_device_request(&self) -> bool {
        self.response_mode == Some("post".to_owned())
    }
}

#[derive(Deserialize, Getters, Debug)]
pub struct Registration {
    #[getset(get = "pub")]
    subject_syntax_types_supported: Option<Vec<String>>,
    _id_token_signing_alg_values_supported: Option<Vec<String>>,
}
