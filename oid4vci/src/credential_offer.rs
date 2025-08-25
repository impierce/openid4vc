use anyhow::Result;
use nutype::nutype;
use oid4vc_core::{to_query_value, JsonObject};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use serde_json::Value;
use serde_with::skip_serializing_none;

/// Grant Type `authorization_code` as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-4.1.1-5.1.1
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AuthorizationCode {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<Url>,
}

/// Grant Type `pre-authorized_code` as described here https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-4.1.1-5.2.1
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct PreAuthorizedCode {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    pub tx_code: Option<TxCodeConstraints>,
    pub interval: Option<i64>,
    pub authorization_server: Option<Url>,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct TxCodeConstraints {
    pub input_mode: Option<InputMode>,
    // Allows a pin-length of 0-255.
    pub length: Option<u8>,
    // The length of the string must not exceed 300 characters.
    pub description: Option<Description>,
    // The length of the string must not exceed 300 characters.
}

#[nutype(
    validate(len_char_max = 300),
    derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)
)]
pub struct Description(String);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum InputMode {
    #[default]
    Numeric,
    Text,
}

/// Credential Offer Parameters as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-credential-offer-parameters
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct CredentialOfferParameters {
    pub credential_issuer: Url,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Option<Grants>,
}

/// Credential Offer as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-credential-offer
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOffer {
    CredentialOfferUri(Url),
    CredentialOffer(Box<CredentialOfferParameters>),
}

impl std::str::FromStr for CredentialOffer {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let map: JsonObject = s
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

impl std::fmt::Display for CredentialOffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialOffer::CredentialOfferUri(uri) => {
                let mut url = Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut().append_pair("credential_offer_uri", uri.as_ref());
                write!(f, "{url}")
            }
            CredentialOffer::CredentialOffer(offer) => {
                let mut url = Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut()
                    .append_pair("credential_offer", &to_query_value(offer).map_err(|_| std::fmt::Error)?);
                write!(f, "{url}")
            }
        }
    }
}

/// Grants as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#section-4.1.1-2.3
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Default)]
pub struct Grants {
    pub authorization_code: Option<AuthorizationCode>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCode>,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, json};

    #[test]
    fn test_credential_offer_serde() {
        let json = json!({
           "credential_issuer": "https://credential-issuer.example.com/",
           "credential_configuration_ids": [
              "UniversityDegree_JWT",
           ],
           "grants": {
              "authorization_code": {
                 "issuer_state": "eyJhbGciOiJSU0Et...FYUaBy"
              },
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                 "pre-authorized_code": "adhjhdjajkdkhjhdj"
              }
           }
        });

        let credential_offer: CredentialOfferParameters = serde_json::from_value(json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_offer,
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credential_configuration_ids: vec!["UniversityDegree_JWT".to_string(),],
                grants: Some(Grants {
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        ..Default::default()
                    }),
                    authorization_code: Some(AuthorizationCode {
                        issuer_state: Some("eyJhbGciOiJSU0Et...FYUaBy".to_string()),
                        authorization_server: None
                    })
                })
            }
        );

        // Assert that the `CredentialOffer` can be serialized back into the original json Value.
        assert_eq!(serde_json::to_value(credential_offer).unwrap(), json);
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/80b2214814106e55e5fd09af3415ba4fc124b6be/examples

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credential_configuration_ids: vec!["UniversityDegree_LDP_VC".to_string(),],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        tx_code: Some(TxCodeConstraints::default()),
                        ..Default::default()
                    })
                })
            },
            from_str::<CredentialOfferParameters>(include_str!("../tests/examples/credential_offer_by_reference.json"))
                .unwrap()
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credential_configuration_ids: vec![
                    "UniversityDegreeCredential".to_string(),
                    "org.iso.18013.5.1.mDL".to_string(),
                ],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "oaKazRN8I0IbtZ0C7JuMn5".to_string(),
                        tx_code: Some(TxCodeConstraints {
                            length: Some(4),
                            input_mode: Some(InputMode::Numeric),
                            description: Description::try_new(
                                "Please provide the one-time code that was sent via e-mail".to_string()
                            )
                            .ok(),
                        }),
                        ..Default::default()
                    })
                })
            },
            from_str::<CredentialOfferParameters>(include_str!(
                "../tests/examples/credential_offer_multiple_credentials.json"
            ))
            .unwrap()
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credential_configuration_ids: vec!["UniversityDegreeCredential".to_string()],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        tx_code: Some(TxCodeConstraints {
                            description: Description::try_new(
                                "Please provide the one-time code which was sent to your mobile phone via SMS"
                                    .to_string()
                            )
                            .ok(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                })
            },
            from_str::<CredentialOfferParameters>(include_str!(
                "../tests/examples/credential_offer_pre-authz_code.json"
            ))
            .unwrap()
        );
    }
}
