use crate::{proof::Proof, CredentialFormat, Format};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

////////////////////
/// https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
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
        proof::{Jwt, Proof},
        JwtVcJson, JwtVcJsonParameters,
    };

    #[test]
    fn test_credential_request() {
        let jwt_vc_json = CredentialFormat {
            format: JwtVcJson,
            parameters: JwtVcJsonParameters {
                credential_definition: CredentialDefinition {
                    type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                    credential_subject: None,
                },
            },
        };

        let credential_request = CredentialRequest {
        credential_format: jwt_vc_json,
        proof: Some(Proof::Jwt { proof_type: Jwt, jwt: "eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM".to_string() }),
    };

        println!("{}", serde_json::to_string_pretty(&credential_request).unwrap());
    }
}
