use super::credentials_supported::CredentialsSupportedObject;
use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use serde_with::skip_serializing_none;

/// Credential Issuer Metadata as described here:
/// https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialIssuerMetadata<CFC = CredentialFormats>
where
    CFC: CredentialFormatCollection,
{
    pub credential_issuer: Url,
    pub authorization_server: Option<Url>,
    pub credential_endpoint: Url,
    pub batch_credential_endpoint: Option<Url>,
    pub deferred_credential_endpoint: Option<Url>,
    pub credentials_supported: Vec<CredentialsSupportedObject<CFC>>,
    pub display: Option<Vec<serde_json::Value>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialsSupportedDisplay {
    name: String,
    locale: Option<String>,
    logo: Option<Logo>,
    description: Option<String>,
    background_color: Option<String>,
    text_color: Option<String>,
    #[serde(flatten)]
    other: Option<Map<String, Value>>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct Logo {
    url: Option<Url>,
    alt_text: Option<String>,
    #[serde(flatten)]
    other: Option<Map<String, Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        iso_mdl::mso_mdoc::MsoMdoc,
        w3c_verifiable_credentials::{
            jwt_vc_json::{self, JwtVcJson},
            ldp_vc::{self, LdpVc},
        },
        CredentialFormats, Parameters,
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::{fs::File, path::Path};

    fn json_example<T>(path: &str) -> T
    where
        T: DeserializeOwned,
    {
        let file_path = Path::new(path);
        let file = File::open(file_path).expect("file does not exist");
        serde_json::from_reader::<_, T>(file).expect("could not parse json")
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://bitbucket.org/openid/connect/src/master/openid-4-verifiable-credential-issuance/examples/.

        assert_eq!(
            CredentialIssuerMetadata {
                credential_endpoint: Url::parse("https://server.example.com/credential").unwrap(),
                credentials_supported: vec![
                    CredentialsSupportedObject {
                        id: Some("UniversityDegree_LDP".to_string()),
                        credential_format: CredentialFormats::LdpVc(Parameters {
                            format: LdpVc,
                            parameters: (
                                ldp_vc::CredentialDefinition {
                                    context: vec![
                                        "https://www.w3.org/2018/credentials/v1".to_string(),
                                        "https://www.w3.org/2018/credentials/examples/v1".to_string(),
                                    ],
                                    type_: vec![
                                        "VerifiableCredential".to_string(),
                                        "UniversityDegreeCredential".to_string()
                                    ],
                                    credential_subject: Some(json!({
                                        "given_name": {
                                            "display": [
                                                {
                                                    "name": "Given Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "名前",
                                                    "locale": "ja-JP"
                                                }
                                            ]
                                        },
                                        "family_name": {
                                            "display": [
                                                {
                                                    "name": "Surname",
                                                    "locale": "en-US"
                                                }
                                            ]
                                        },
                                        "degree": {},
                                        "gpa": {
                                            "display": [
                                                {
                                                    "name": "GPA"
                                                }
                                            ]
                                        }
                                    }))
                                },
                                None
                            )
                                .into()
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: Some(vec!["did".to_string()]),
                        cryptographic_suites_supported: Some(vec!["Ed25519Signature2018".to_string()]),
                        proof_types_supported: None,
                        display: Some(vec![
                            json!({
                                "name": "University Credential",
                                "locale": "en-US",
                                "logo": {
                                    "url": "https://exampleuniversity.com/public/logo.png",
                                    "alternative_text": "a square logo of a university"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }),
                            json!({
                                "name": "在籍証明書",
                                "locale": "ja-JP",
                                "logo": {
                                    "url": "https://exampleuniversity.com/public/logo.png",
                                    "alternative_text": "大学のロゴ"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            })
                        ]),
                    },
                    CredentialsSupportedObject {
                        id: None,
                        credential_format: CredentialFormats::JwtVcJson(Parameters {
                            format: JwtVcJson,
                            parameters: (
                                jwt_vc_json::CredentialDefinition {
                                    type_: vec![
                                        "VerifiableCredential".to_string(),
                                        "UniversityDegreeCredential".to_string()
                                    ],
                                    credential_subject: Some(json!({
                                        "given_name": {
                                            "display": [
                                                {
                                                    "name": "Given Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "名前",
                                                    "locale": "ja-JP"
                                                }
                                            ]
                                        },
                                        "family_name": {
                                            "display": [
                                                {
                                                    "name": "Surname",
                                                    "locale": "en-US"
                                                }
                                            ]
                                        },
                                        "degree": {},
                                        "gpa": {
                                            "display": [
                                                {
                                                    "name": "GPA"
                                                }
                                            ]
                                        }
                                    }))
                                },
                                None
                            )
                                .into()
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: Some(vec!["did".to_string()]),
                        cryptographic_suites_supported: Some(vec!["ES256K".to_string()]),
                        proof_types_supported: None,
                        display: Some(vec![
                            json!({
                                "name": "University Credential",
                                "locale": "en-US",
                                "logo": {
                                    "url": "https://exampleuniversity.com/public/logo.png",
                                    "alternative_text": "a square logo of a university"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }),
                            json!({
                                "name": "在籍証明書",
                                "locale": "ja-JP",
                                "logo": {
                                    "url": "https://exampleuniversity.com/public/logo.png",
                                    "alternative_text": "大学のロゴ"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            })
                        ]),
                    },
                    CredentialsSupportedObject {
                        id: None,
                        credential_format: CredentialFormats::MsoMdoc(Parameters {
                            format: MsoMdoc,
                            parameters: (
                                "org.iso.18013.5.1.mDL".to_string(),
                                Some(json!({
                                    "org.iso.18013.5.1": {
                                        "given_name": {
                                            "display": [
                                                {
                                                    "name": "Given Name",
                                                    "locale": "en-US"
                                                },
                                                {
                                                    "name": "名前",
                                                    "locale": "ja-JP"
                                                }
                                            ]
                                        },
                                        "family_name": {
                                            "display": [
                                                {
                                                    "name": "Surname",
                                                    "locale": "en-US"
                                                }
                                            ]
                                        },
                                        "birth_date": {}
                                    },
                                    "org.iso.18013.5.1.aamva": {
                                        "organ_donor": {}
                                    }
                                })),
                                None
                            )
                                .into()
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: Some(vec!["mso".to_string()]),
                        cryptographic_suites_supported: Some(vec![
                            "ES256".to_string(),
                            "ES384".to_string(),
                            "ES512".to_string()
                        ]),
                        proof_types_supported: None,
                        display: Some(vec![
                            json!({
                                "name": "Mobile Driving License",
                                "locale": "en-US",
                                "logo": {
                                    "url": "https://examplestate.com/public/mdl.png",
                                    "alternative_text": "a square figure of a mobile driving license"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }),
                            json!({
                                "name": "在籍証明書",
                                "locale": "ja-JP",
                                "logo": {
                                    "url": "https://examplestate.com/public/mdl.png",
                                    "alternative_text": "大学のロゴ"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            })
                        ]),
                    }
                ],
                credential_issuer: "https://server.example.com".parse().unwrap(),
                authorization_server: None,
                batch_credential_endpoint: None,
                deferred_credential_endpoint: None,
                display: None,
            },
            json_example::<CredentialIssuerMetadata<CredentialFormats>>("tests/examples/issuer_metadata.json")
        );
    }
}
