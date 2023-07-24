use crate::{proof::Proof, CredentialFormat, Format};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialRequest<F>
where
    F: Format,
{
    #[serde(flatten)]
    pub credential_format: CredentialFormat<F>,
    pub proof: Option<Proof>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        credential_definition::CredentialDefinition,
        credential_format_profiles::{iso_mdl::mso_mdoc::MsoMdoc, w3c_verifiable_credentials::jwt_vc_json::JwtVcJson},
        Jwt,
    };
    use serde_json::json;

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

        let credential_request_jwt_vc_json: CredentialRequest<JwtVcJson> =
            serde_json::from_value(jwt_vc_json.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_request_jwt_vc_json,
            CredentialRequest {
                credential_format: CredentialFormat {
                    format: JwtVcJson,
                    parameters: CredentialDefinition {
                        type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                        credential_subject: Some(json!({
                            "given_name": {},
                            "family_name": {},
                            "degree": {}
                        })),
                    }
                    .into()
                },
                proof: Some(Proof::Jwt {
                    proof_type: Jwt,
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".into()
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

        let credential_request_mso_mdoc: CredentialRequest<MsoMdoc> = serde_json::from_value(mso_mdoc.clone()).unwrap();

        // Assert that the json Value is deserialized into the correct type.
        assert_eq!(
            credential_request_mso_mdoc,
            CredentialRequest {
                credential_format: CredentialFormat {
                    format: MsoMdoc,
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
                },
                proof: Some(Proof::Jwt {
                    proof_type: Jwt,
                    jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZ...KPxgihac0aW9EkL1nOzM".into()
                })
            },
        );

        // Assert that the `CredentialRequest` can be serialized back into the original json Value.
        assert_eq!(serde_json::to_value(credential_request_mso_mdoc).unwrap(), mso_mdoc);
    }
}
