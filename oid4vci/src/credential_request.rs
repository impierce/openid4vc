use crate::{
    credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithParameters},
    proof::KeyProofType,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credential Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-credential-request.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct CredentialRequest<CFC = CredentialFormats<WithParameters>>
where
    CFC: CredentialFormatCollection,
{
    #[serde(flatten)]
    pub credential_format: CFC,
    pub proof: Option<KeyProofType>,
    // TODO: add `credential_identifier` field when support for Authorization Code Flow is added.
    // TODO: add `credential_encryption_jwk`, `credential_response_encryption_alg` and
    // `credential_response_encryption_enc` fields when support for JWE is added.
}

/// Batch Credential Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#name-batch-credential-request.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchCredentialRequest<CFC = CredentialFormats>
where
    CFC: CredentialFormatCollection,
{
    pub credential_requests: Vec<CredentialRequest<CFC>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_format_profiles::{
        w3c_verifiable_credentials::{
            jwt_vc_json::{self, CredentialDefinition},
            jwt_vc_json_ld, ldp_vc,
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
    fn test_credential_request_serde_jwt_vc_json() {
        let jwt_vc_json = json!({
            "format": "jwt_vc_json",
            "credential_definition": {
               "type": [
                  "VerifiableCredential",
                  "UniversityDegreeCredential"
               ],
               "credentialSubject": {
                  "given_name": {},
                  "family_name": {},
                  "degree": {}
               }
            },
            "proof": {
               "proof_type": "jwt",
               "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
            }
        });

        let credential_request_jwt_vc_json: CredentialRequest = serde_json::from_value(jwt_vc_json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_request_jwt_vc_json,
            CredentialRequest {
                credential_format: CredentialFormats::JwtVcJson(Parameters {
                    parameters: (
                        CredentialDefinition {
                            type_: vec![
                                "VerifiableCredential".to_string(),
                                "UniversityDegreeCredential".to_string()
                            ],
                            credential_subject: Some(json!({
                                "given_name": {},
                                "family_name": {},
                                "degree": {}
                            })),
                        },
                        None
                    )
                        .into()
                }),
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".to_string()
                })
            },
        );

        // Assert that the `CredentialRequest` can be serialized back into the original json Value.
        assert_eq!(
            serde_json::to_value(credential_request_jwt_vc_json).unwrap(),
            jwt_vc_json
        );
    }

    #[test]
    fn test_credential_request_serde_mso_mdoc() {
        let mso_mdoc = json!({
            "format": "mso_mdoc",
            "doctype": "org.iso.18013.5.1.mDL",
            "claims": {
               "org.iso.18013.5.1": {
                  "given_name": {},
                  "family_name": {},
                  "birth_date": {}
               },
               "org.iso.18013.5.1.aamva": {
                  "organ_donor": {}
               }
            },
            "proof": {
               "proof_type": "jwt",
               "jwt": "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM"
            }
        });

        let credential_request_mso_mdoc: CredentialRequest = serde_json::from_value(mso_mdoc.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_request_mso_mdoc,
            CredentialRequest {
                credential_format: CredentialFormats::MsoMdoc(Parameters {
                    parameters: (
                        "org.iso.18013.5.1.mDL".to_string(),
                        Some(json!({
                            "org.iso.18013.5.1": {
                                "given_name": {},
                                "family_name": {},
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
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".to_string()
                })
            },
        );

        // Assert that the `CredentialRequest` can be serialized back into the original json Value.
        assert_eq!(serde_json::to_value(credential_request_mso_mdoc).unwrap(), mso_mdoc);
    }

    #[test]
    fn test_oid4vci_examples() {
        // Examples from
        // https://github.com/openid/OpenID4VCI/tree/f7985f6120cbcd51fd971a320a61606da14e2580/examples.

        assert_eq!(
            CredentialRequest {
                credential_format: CredentialFormats::MsoMdoc(Parameters {
                    parameters: ("org.iso.18013.5.1.mDL".to_string(), None, None).into()
                }),
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".to_string()
                })
            },
            json_example::<CredentialRequest>("tests/examples/credential_request_iso_mdl.json")
        );

        assert_eq!(
            CredentialRequest {
                credential_format: CredentialFormats::MsoMdoc(Parameters {
                    parameters: (
                        "org.iso.18013.5.1.mDL".to_string(),
                        Some(json!({
                            "org.iso.18013.5.1": {
                                "given_name": {},
                                "family_name": {},
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
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".to_string()
                })
            },
            json_example::<CredentialRequest>("tests/examples/credential_request_iso_mdl_with_claims.json")
        );

        assert_eq!(
            CredentialRequest {
                credential_format: CredentialFormats::JwtVcJsonLd(Parameters {
                    parameters: (
                        jwt_vc_json_ld::CredentialDefinition {
                            context: vec![
                                "https://www.w3.org/2018/credentials/v1".to_string(),
                                "https://www.w3.org/2018/credentials/examples/v1".to_string()
                            ],
                            type_: vec![
                                "VerifiableCredential".to_string(),
                                "UniversityDegreeCredential".to_string()
                            ],
                            credential_subject: Some(json!({
                                "degree": {
                                    "type":{}
                                }
                            })),
                        },
                        None
                    )
                        .into()
                }),
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".to_string()
                })
            },
            json_example::<CredentialRequest>("tests/examples/credential_request_jwt_vc_json-ld.json")
        );

        assert_eq!(
            CredentialRequest {
                credential_format: CredentialFormats::JwtVcJson(Parameters {
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
                }),
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM".to_string()
                })
            },
            json_example::<CredentialRequest>(
                "tests/examples/credential_request_jwt_vc_json.json"
            )
        );

        assert_eq!(
            CredentialRequest {
                credential_format: CredentialFormats::JwtVcJson(Parameters {
                    parameters: (
                        jwt_vc_json::CredentialDefinition {
                            type_: vec![
                                "VerifiableCredential".to_string(),
                                "UniversityDegreeCredential".to_string()
                            ],
                            credential_subject: Some(json!({
                                    "given_name": {},
                                    "family_name": {},
                                    "degree": {}
                            }))
                        },
                        None
                    )
                        .into()
                }),
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM".to_string()
                })
            },
            json_example::<CredentialRequest>(
                "tests/examples/credential_request_jwt_vc_json_with_claims.json"
            )
        );

        assert_eq!(
            CredentialRequest {
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
                                    "degree": {
                                        "type": {}
                                    }
                            }))
                        },
                        None
                    )
                        .into()
                }),
                proof: Some(KeyProofType::Jwt {
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".to_string()
                })
            },
            json_example::<CredentialRequest>("tests/examples/credential_request_ldp_vc.json")
        );
    }
}
