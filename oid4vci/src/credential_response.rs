use crate::credential_format_profiles::{
    w3c_verifiable_credentials::jwt_vc_json::{CredentialDefinition, JwtVcJson},
    CredentialFormat, CredentialFormatCollection, CredentialFormats,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_with::skip_serializing_none;

/// Credential Response as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response.
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct CredentialResponse<CFC = CredentialFormats>
where
    CFC: CredentialFormatCollection,
{
    #[serde(flatten)]
    pub credential: CredentialResponseType<CFC>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct BatchCredentialResponse {
    pub credential_responses: Vec<CredentialResponseType>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum CredentialResponseType<CFC = CredentialFormats>
where
    CFC: CredentialFormatCollection,
{
    Immediate {
        #[serde(flatten)]
        // format: CFC2,
        temp: CFC,
        credential: Option<serde_json::Value>,
    },
    Deferred {
        transaction_id: String,
    },
}

#[test]
fn test() {
    let temp: CredentialResponse = CredentialResponse {
        credential: CredentialResponseType::Immediate {
            temp: CredentialFormats::JwtVcJson(CredentialFormat {
                format: JwtVcJson,
                parameters: (
                    CredentialDefinition {
                        type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                        credential_subject: None,
                    },
                    None,
                )
                    .into(),
            }),
            credential: Some(json!({
                "some": "credential"
            })),
        },
        c_nonce: None,
        c_nonce_expires_in: None,
    };

    println!("{}", serde_json::to_string_pretty(&temp).unwrap());
}
