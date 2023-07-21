use anyhow::Result;
use oid4vc_core::to_query_value;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::skip_serializing_none;
use std::hash::{Hash, Hasher};

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AuthorizationCode {
    pub issuer_state: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct PreAuthorizedCode {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub user_pin_required: bool,
    #[serde(default = "default_interval")]
    pub interval: i64,
}

impl Hash for PreAuthorizedCode {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pre_authorized_code.hash(state);
    }
}

fn default_interval() -> i64 {
    5
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
pub struct CredentialOffer {
    pub credential_issuer: Url,
    pub credentials: Vec<serde_json::Value>,
    pub grants: Option<Grants>,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOfferQuery {
    CredentialOfferUri(Url),
    CredentialOffer(CredentialOffer),
}

impl std::str::FromStr for CredentialOfferQuery {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let map: Map<String, Value> = s
            .parse::<Url>()?
            .query_pairs()
            .map(|(key, value)| {
                let value = serde_json::from_str::<Value>(&value).unwrap_or(Value::String(value.into_owned()));
                Ok((key.into_owned(), value))
            })
            .collect::<Result<_>>()?;
        serde_json::from_value(Value::Object(map)).map_err(Into::into)
    }
}

impl std::fmt::Display for CredentialOfferQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialOfferQuery::CredentialOfferUri(url) => write!(f, "{}", url),
            CredentialOfferQuery::CredentialOffer(offer) => {
                let mut url = Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut()
                    .append_pair("credential_offer", &to_query_value(offer).map_err(|_| std::fmt::Error)?);
                write!(f, "{}", url)
            }
        }
    }
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct Grants {
    pub authorization_code: Option<AuthorizationCode>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCode>,
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderName;
    use wiremock::{
        http::HeaderValue,
        matchers::{method, path},
        Mock, MockServer, Request, ResponseTemplate,
    };

    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn temp() {
        #[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
        struct Claims {
            response_type: String,
            client_id: String,
            redirect_uri: Url,
        }

        let client = reqwest::Client::new();

        let issuer = MockServer::start().await;
        let wallet = MockServer::start().await;

        let issuer_url = issuer.uri();

        Mock::given(method("GET"))
            .and(path("/authorize"))
            .respond_with(move |req: &Request| {
                let claims: Claims = serde_urlencoded::from_bytes(req.body.as_slice()).unwrap();
                ResponseTemplate::new(302).append_header(
                    HeaderName::from_str("Location").unwrap(),
                    HeaderValue::from_str(&format!("{}?code=SplxlOBeZQQYbYS6WxSbIA", claims.redirect_uri.as_str()))
                        .unwrap(),
                )
            })
            .mount(&issuer)
            .await;
        let wallet_url = wallet.uri();

        Mock::given(method("GET"))
            .and(path("/cb"))
            .respond_with(|req: &Request| {
                dbg!(req);
                ResponseTemplate::new(200)
            })
            .mount(&wallet)
            .await;

        let response = client
            .get(&format!("{}/authorize", issuer_url))
            .form(&Claims {
                response_type: "code".to_string(),
                client_id: "CLIENT1234".to_string(),
                redirect_uri: Url::from_str(&format!("{}/cb", wallet_url)).unwrap(),
            })
            .send()
            .await
            .unwrap();
        dbg!(&response);
    }
}
