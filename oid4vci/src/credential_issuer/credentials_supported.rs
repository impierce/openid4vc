use crate::{
    credential_format_profiles::{CredentialFormat, Format},
    ProofType,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credentials Supported object as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-objects-comprising-credenti.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialsSupportedObject<F>
where
    F: Format,
{
    id: Option<String>,
    #[serde(flatten)]
    credential_format: CredentialFormat<F>,
    scope: Option<String>,
    cryptographic_binding_methods_supported: Option<Vec<String>>,
    cryptographic_suites_supported: Option<Vec<String>>,
    proof_types_supported: Option<Vec<ProofType>>,
    display: Option<Vec<serde_json::Value>>,
}

/// Credentials Supported object as a json Value, needed in order to be able to deserialize the object into the correct type.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialsSupportedJson(pub serde_json::Value);

impl<F: Format> From<CredentialsSupportedObject<F>> for CredentialsSupportedJson {
    fn from(value: CredentialsSupportedObject<F>) -> Self {
        CredentialsSupportedJson(serde_json::to_value(value).unwrap())
    }
}

impl<'de, F: Format + DeserializeOwned> TryInto<CredentialFormat<F>> for CredentialsSupportedJson
where
    CredentialFormat<F>: Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_into(self) -> Result<CredentialFormat<F>, Self::Error> {
        serde_json::from_value(self.0)
    }
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
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::{fs::File, path::Path};

    #[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
    #[serde(untagged)]
    enum CredentialsSupportedObjectEnum {
        JwtVcJson(CredentialsSupportedObject<JwtVcJson>),
        LdpVc(CredentialsSupportedObject<LdpVc>),
        MsoMdoc(CredentialsSupportedObject<MsoMdoc>),
        Other(serde_json::Value),
    }

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
            CredentialsSupportedObjectEnum::JwtVcJson(CredentialsSupportedObject {
                id: Some("UniversityDegree_JWT".to_string()),
                credential_format: CredentialFormat {
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
                            })),
                        },
                        None
                    )
                        .into()
                },
                scope: None,
                cryptographic_binding_methods_supported: Some(vec!["did:example".to_string()]),
                cryptographic_suites_supported: Some(vec!["ES256K".to_string()]),
                proof_types_supported: Some(vec![ProofType::Jwt]),
                display: Some(vec![json!({
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                })])
            }),
            json_example::<CredentialsSupportedObjectEnum>("tests/examples/credential_metadata_jwt_vc_json.json")
        );

        assert_eq!(
            CredentialsSupportedObjectEnum::LdpVc(CredentialsSupportedObject {
                id: None,
                credential_format: CredentialFormat {
                    format: LdpVc,
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
                            credential_subject: Some(json!({
                                "given_name": {
                                    "display": [
                                        {
                                            "name": "Given Name",
                                            "locale": "en-US"
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
                            })),
                        },
                        None
                    )
                        .into()
                },
                scope: None,
                cryptographic_binding_methods_supported: Some(vec!["did:example".to_string()]),
                cryptographic_suites_supported: Some(vec!["Ed25519Signature2018".to_string()]),
                proof_types_supported: None,
                display: Some(vec![json!({
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university"
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                })])
            }),
            json_example::<CredentialsSupportedObjectEnum>("tests/examples/credential_metadata_ldp_vc.json")
        );

        assert_eq!(
            CredentialsSupportedObjectEnum::MsoMdoc(CredentialsSupportedObject {
                id: None,
                credential_format: CredentialFormat {
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
                },
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
                            "alt_text": "a square figure of a mobile driving license"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    }),
                    json!({
                        "name": "在籍証明書",
                        "locale": "ja-JP",
                        "logo": {
                            "url": "https://examplestate.com/public/mdl.png",
                            "alt_text": "大学のロゴ"
                        },
                        "background_color": "#12107c",
                        "text_color": "#FFFFFF"
                    })
                ])
            }),
            json_example::<CredentialsSupportedObjectEnum>("tests/examples/credential_metadata_mso_mdoc.json")
        );
    }
}
