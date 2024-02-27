use anyhow::Result;
use oid4vc_core::{to_query_value, JsonObject};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::skip_serializing_none;

/// Grant Type `authorization_code` as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#section-4.1.1-4.1.1.
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AuthorizationCode {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<Url>,
}

/// Grant Type `pre-authorized_code` as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#section-4.1.1-4.2.1.
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct PreAuthorizedCode {
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    #[serde(default)]
    pub user_pin_required: bool,
    pub interval: Option<i64>,
    pub authorization_server: Option<Url>,
}

/// Credential Offer Parameters as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-credential-offer-parameters.
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
pub struct CredentialOfferParameters {
    pub credential_issuer: Url,
    pub credentials: Vec<String>,
    pub grants: Option<Grants>,
}

/// Credential Offer as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-credential-offer.
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOffer {
    CredentialOfferUri(Url),
    CredentialOffer(CredentialOfferParameters),
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
                url.query_pairs_mut().append_pair(
                    "credential_offer_uri",
                    &to_query_value(uri).map_err(|_| std::fmt::Error)?,
                );
                write!(f, "{}", url)
            }
            CredentialOffer::CredentialOffer(offer) => {
                let mut url = Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut()
                    .append_pair("credential_offer", &to_query_value(offer).map_err(|_| std::fmt::Error)?);
                write!(f, "{}", url)
            }
        }
    }
}

/// Grants as described in https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#section-4.1.1-2.3.
#[skip_serializing_none]
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone, Default)]
pub struct Grants {
    pub authorization_code: Option<AuthorizationCode>,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    pub pre_authorized_code: Option<PreAuthorizedCode>,
}

#[cfg(test)]
mod tests {
    use std::{fs::File, path::Path};

    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::json;

    fn json_example<T>(path: &str) -> T
    where
        T: DeserializeOwned,
    {
        let file_path = Path::new(path);
        let file = File::open(file_path).expect("file does not exist");
        serde_json::from_reader::<_, T>(file).expect("could not parse json")
    }

    #[test]
    fn test_credential_offer_serde() {
        let json = json!({
           "credential_issuer": "https://credential-issuer.example.com/",
           "credentials": [
              "UniversityDegree_JWT",
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

        let credential_offer: CredentialOfferParameters = serde_json::from_value(json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_offer,
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec!["UniversityDegree_JWT".to_string(),],
                grants: Some(Grants {
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
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
        // https://github.com/openid/OpenID4VCI/tree/f7985f6120cbcd51fd971a320a61606da14e2580/examples.

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec!["UniversityDegree_LDP".to_string(),],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOfferParameters>("tests/examples/credential_offer_by_reference.json")
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec!["UniversityDegreeCredential".to_string(),],
                grants: Some(Grants {
                    authorization_code: Some(AuthorizationCode {
                        issuer_state: Some("eyJhbGciOiJSU0Et...FYUaBy".to_string()),
                        authorization_server: None
                    }),
                    pre_authorized_code: None
                })
            },
            json_example::<CredentialOfferParameters>("tests/examples/credential_offer_jwt_vc_json.json")
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec!["UniversityDegree_LDP_VC".to_string()],
                grants: None
            },
            json_example::<CredentialOfferParameters>("tests/examples/credential_offer_ldp_vc.json")
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec!["org.iso.18013.5.1.mDL".to_string(),],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOfferParameters>("tests/examples/credential_offer_mso_mdoc.json")
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![
                    "UniversityDegreeCredential".to_string(),
                    "org.iso.18013.5.1.mDL".to_string(),
                ],
                grants: Some(Grants {
                    authorization_code: Some(AuthorizationCode {
                        issuer_state: Some("eyJhbGciOiJSU0Et...FYUaBy".to_string()),
                        authorization_server: None
                    }),
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOfferParameters>("tests/examples/credential_offer_multiple_credentials.json")
        );

        assert_eq!(
            CredentialOfferParameters {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec!["UniversityDegreeCredential".to_string()],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOfferParameters>("tests/examples/credential_offer_pre-authz_code.json")
        );
    }
}
