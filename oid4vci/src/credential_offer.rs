use anyhow::Result;
use oid4vc_core::to_query_value;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::skip_serializing_none;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AuthorizationCode {
    pub issuer_state: Option<String>,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct PreAuthorizedCode {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub user_pin_required: bool,
    pub interval: Option<i64>,
}

/// Credential Offer as described in https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer.
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
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

/// Grants as described in https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters.
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Default)]
pub struct Grants {
    pub authorization_code: Option<AuthorizationCode>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCode>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{iso_mdl::mso_mdoc::MsoMdoc, CredentialFormat};
    use serde_json::json;

    #[test]
    fn test_credential_offer_serde() {
        let json = json!({
           "credential_issuer": "https://credential-issuer.example.com/",
           "credentials": [
              "UniversityDegree_JWT",
              {
                 "format": "mso_mdoc",
                 "doctype": "org.iso.18013.5.1.mDL"
              }
           ],
           "grants": {
              "authorization_code": {
                 "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
              },
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                 "pre-authorized_code": "adhjhdjajkdkhjhdj",
                 "user_pin_required": true
              }
           }
        });

        let credential_offer: CredentialOffer = serde_json::from_value(json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_offer,
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![
                    serde_json::Value::String("UniversityDegree_JWT".into()),
                    serde_json::to_value(CredentialFormat {
                        format: MsoMdoc,
                        parameters: ("org.iso.18013.5.1.mDL".to_string(), None, None).into()
                    })
                    .unwrap()
                ],
                grants: Some(Grants {
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    }),
                    authorization_code: Some(AuthorizationCode {
                        issuer_state: Some("eyJhbGciOiJSU0Et...FYUaBy".to_string())
                    })
                })
            }
        );

        // Assert that the `CredentialOffer` can be serialized back into the original json Value.
        assert_eq!(serde_json::to_value(credential_offer).unwrap(), json);
    }
}
