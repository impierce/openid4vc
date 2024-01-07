use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters};
use anyhow::Result;
use oid4vc_core::{to_query_value, JsonObject};
use reqwest::Url;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
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
pub struct CredentialOffer<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    pub credential_issuer: Url,
    pub credentials: Vec<CredentialsObject<CFC>>,
    pub grants: Option<Grants>,
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOfferQuery<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    CredentialOfferUri(Url),
    CredentialOffer(CredentialOffer<CFC>),
}

impl<CFC: CredentialFormatCollection + DeserializeOwned> std::str::FromStr for CredentialOfferQuery<CFC> {
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

impl<CFC: CredentialFormatCollection> std::fmt::Display for CredentialOfferQuery<CFC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialOfferQuery::CredentialOfferUri(uri) => {
                let mut url = Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut().append_pair(
                    "credential_offer_uri",
                    &to_query_value(uri).map_err(|_| std::fmt::Error)?,
                );
                write!(f, "{}", url)
            }
            CredentialOfferQuery::CredentialOffer(offer) => {
                let mut url = Url::parse("openid-credential-offer://").map_err(|_| std::fmt::Error)?;
                url.query_pairs_mut()
                    .append_pair("credential_offer", &to_query_value(offer).map_err(|_| std::fmt::Error)?);
                write!(f, "{}", url)
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Eq, PartialEq, Clone)]
#[serde(untagged)]
pub enum CredentialsObject<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    ByReference(String),
    ByValue(CFC),
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
    use std::{fs::File, path::Path};

    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{jwt_vc_json, ldp_vc},
        CredentialFormats, Parameters,
    };
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
                    CredentialsObject::ByReference("UniversityDegree_JWT".to_string()),
                    CredentialsObject::ByValue(CredentialFormats::MsoMdoc(Parameters {
                        parameters: ("org.iso.18013.5.1.mDL".to_string(), None, None).into()
                    }))
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

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://bitbucket.org/openid/connect/src/master/openid-4-verifiable-credential-issuance/examples/.

        assert_eq!(
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![CredentialsObject::ByReference("UniversityDegree_LDP".to_string()),],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOffer>("tests/examples/credential_offer_by_reference.json")
        );

        assert_eq!(
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![CredentialsObject::ByValue(CredentialFormats::JwtVcJson(Parameters {
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
                            type_: vec![
                                "VerifiableCredential".to_string(),
                                "UniversityDegreeCredential".to_string()
                            ],
                            credential_subject: None
                        },
                        None
                    )
                        .into()
                })),],
                grants: Some(Grants {
                    authorization_code: Some(AuthorizationCode {
                        issuer_state: Some("eyJhbGciOiJSU0Et...FYUaBy".to_string())
                    }),
                    pre_authorized_code: None
                })
            },
            json_example::<CredentialOffer>("tests/examples/credential_offer_jwt_vc_json.json")
        );

        assert_eq!(
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![CredentialsObject::ByValue(CredentialFormats::LdpVc(Parameters {
                    parameters: (
                        ldp_vc::CredentialDefinition {
                            context: vec![
                                "https://www.w3.org/2018/credentials/v1".to_string(),
                                "https://www.w3.org/2018/credentials/examples/v1".to_string()
                            ],
                            type_: vec![
                                "VerifiableCredential".to_string(),
                                "UniversityDegreeCredential".to_string()
                            ],
                            credential_subject: None
                        },
                        None
                    )
                        .into()
                })),],
                grants: None
            },
            json_example::<CredentialOffer>("tests/examples/credential_offer_ldp_vc.json")
        );

        assert_eq!(
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![CredentialsObject::ByValue(CredentialFormats::MsoMdoc(Parameters {
                    parameters: ("org.iso.18013.5.1.mDL".to_string(), None, None).into()
                })),],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOffer>("tests/examples/credential_offer_mso_mdoc.json")
        );

        assert_eq!(
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![
                    CredentialsObject::ByReference("UniversityDegree_JWT".to_string()),
                    CredentialsObject::ByValue(CredentialFormats::MsoMdoc(Parameters {
                        parameters: ("org.iso.18013.5.1.mDL".to_string(), None, None).into()
                    })),
                ],
                grants: Some(Grants {
                    authorization_code: Some(AuthorizationCode {
                        issuer_state: Some("eyJhbGciOiJSU0Et...FYUaBy".to_string())
                    }),
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOffer>("tests/examples/credential_offer_multiple_credentials.json")
        );

        assert_eq!(
            CredentialOffer {
                credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
                credentials: vec![CredentialsObject::ByValue(CredentialFormats::JwtVcJson(Parameters {
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
                            type_: vec![
                                "VerifiableCredential".to_string(),
                                "UniversityDegreeCredential".to_string()
                            ],
                            credential_subject: None
                        },
                        None
                    )
                        .into()
                })),],
                grants: Some(Grants {
                    authorization_code: None,
                    pre_authorized_code: Some(PreAuthorizedCode {
                        pre_authorized_code: "adhjhdjajkdkhjhdj".to_string(),
                        user_pin_required: true,
                        ..Default::default()
                    })
                })
            },
            json_example::<CredentialOffer>("tests/examples/credential_offer_pre-authz_code.json")
        );
    }
}
