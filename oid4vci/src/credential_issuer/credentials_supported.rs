use std::collections::HashMap;

use crate::{
    credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters},
    proof::KeyProofMetadata,
    ProofType,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credentials Supported object as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#section-10.2.3-2.11.1.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialsSupportedObject<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    /// This field is flattened into a `format` field and optionally extra format-specific fields.
    #[serde(flatten)]
    pub credential_format: CFC,
    // Use `Scope` from oid4vc-core/src/scope.rs.
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub cryptographic_binding_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub credential_signing_alg_values_supported: Vec<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub proof_types_supported: HashMap<ProofType, KeyProofMetadata>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub display: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{jwt_vc_json, ldp_vc},
        CredentialFormats, Parameters,
    };
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::{collections::HashMap, fs::File, path::Path};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestWrapper {
        credentials_supported: HashMap<String, CredentialsSupportedObject>,
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
        // https://github.com/openid/OpenID4VCI/tree/f7985f6120cbcd51fd971a320a61606da14e2580/examples.

        assert_eq!(
            TestWrapper {
                credentials_supported: vec![(
                    "UniversityDegreeCredential".to_string(),
                    CredentialsSupportedObject {
                        credential_format: CredentialFormats::JwtVcJson(Parameters {
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
                        }),
                        scope: Some("UniversityDegree".to_string()),
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec!["ES256K".to_string()],
                        proof_types_supported: vec![(
                            ProofType::Jwt,
                            KeyProofMetadata {
                                proof_signing_alg_values_supported: vec!["ES256".to_string()]
                            }
                        )]
                        .into_iter()
                        .collect(),
                        display: vec![json!({
                            "name": "University Credential",
                            "locale": "en-US",
                            "logo": {
                                "url": "https://exampleuniversity.com/public/logo.png",
                                "alt_text": "a square logo of a university"
                            },
                            "background_color": "#12107c",
                            "text_color": "#FFFFFF"
                        })]
                    }
                )]
                .into_iter()
                .collect()
            },
            json_example::<TestWrapper>("tests/examples/credential_metadata_jwt_vc_json.json")
        );

        assert_eq!(
            TestWrapper {
                credentials_supported: vec![(
                    "UniversityDegree_LDP_VC".to_string(),
                    CredentialsSupportedObject {
                        credential_format: CredentialFormats::LdpVc(Parameters {
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
                        }),
                        scope: None,
                        cryptographic_binding_methods_supported: vec!["did:example".to_string()],
                        credential_signing_alg_values_supported: vec!["Ed25519Signature2018".to_string()],
                        proof_types_supported: HashMap::new(),
                        display: vec![json!({
                                "name": "University Credential",
                                "locale": "en-US",
                                "logo": {
                                    "url": "https://exampleuniversity.com/public/logo.png",
                                    "alt_text": "a square logo of a university"
                                },
                                "background_color": "#12107c",
                                "text_color": "#FFFFFF"
                            }
                        )]
                    },
                )]
                .into_iter()
                .collect()
            },
            json_example::<TestWrapper>("tests/examples/credential_metadata_ldp_vc.json")
        );

        assert_eq!(
            TestWrapper {
                credentials_supported: vec![(
                    "org.iso.18013.5.1.mDL".to_string(),
                    CredentialsSupportedObject {
                        credential_format: CredentialFormats::MsoMdoc(Parameters {
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
                        cryptographic_binding_methods_supported: vec!["mso".to_string()],
                        credential_signing_alg_values_supported: vec![
                            "ES256".to_string(),
                            "ES384".to_string(),
                            "ES512".to_string()
                        ],
                        proof_types_supported: HashMap::new(),
                        display: vec![
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
                        ]
                    }
                )]
                .into_iter()
                .collect()
            },
            json_example::<TestWrapper>("tests/examples/credential_metadata_mso_mdoc.json")
        );
    }
}
