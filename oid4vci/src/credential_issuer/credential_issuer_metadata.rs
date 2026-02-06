use super::credential_configurations_supported::CredentialConfigurationsSupportedObject;
use derivative::Derivative;
use nutype::nutype;
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CredentialResponseEncryption {
    pub alg_values_supported: Vec<String>,
    pub enc_values_supported: Vec<String>,
    pub encryption_required: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BatchCredentialIssuance {
    pub batch_size: BatchSize,
}

#[nutype(validate(predicate = |value: &u32| *value >= 2),
         derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize))]
pub struct BatchSize(u32);

/// Credential Issuer Metadata as described here:
/// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-15.html#name-credential-issuer-metadata-p
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Derivative)]
#[derivative(Default)]
pub struct CredentialIssuerMetadata {
    // TODO: Temporary solution
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub credential_issuer: Url,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authorization_servers: Vec<Url>,
    // TODO: Temporary solution
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub credential_endpoint: Url,
    pub nonce_endpoint: Option<Url>,
    pub deferred_credential_endpoint: Option<Url>,
    pub notification_endpoint: Option<Url>,
    pub credential_response_encryption: Option<CredentialResponseEncryption>,
    pub credential_identifiers_supported: Option<bool>,
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,
    pub signed_metadata: Option<String>,
    pub display: Option<Vec<serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_credential_configurations_supported")]
    pub credential_configurations_supported: HashMap<String, CredentialConfigurationsSupportedObject>,
}

// A custom deserialization function to filter out invalid map entries.
fn deserialize_credential_configurations_supported<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, CredentialConfigurationsSupportedObject>, D::Error>
where
    D: Deserializer<'de>,
{
    // First, deserialize into a map of raw JSON values. This will not fail
    // unless the JSON structure itself is not a map.
    let map: HashMap<String, serde_json::Value> = HashMap::deserialize(deserializer)?;

    // Iterate over the raw map and try to deserialize each value.
    // Collect only the ones that succeed.
    let valid_map = map
        .into_iter()
        .filter_map(|(key, value)| {
            serde_json::from_value::<CredentialConfigurationsSupportedObject>(value)
                .ok()
                .map(|credential_configuration| (key, credential_configuration))
        })
        .collect();

    Ok(valid_map)
}

// TODO! Update test once we have the credential_request_encryption field implemented.

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::{
    //     credential_format_profiles::{
    //         w3c_verifiable_credentials::{jwt_vc_json, CredentialSubject},
    //         CredentialFormats, Parameters, WithParameters,
    //     },
    //     credential_issuer::credential_configurations_supported::{
    //         AlgIdentifier, ClaimDescription, CredentialConfigurationsSupportedObject, CredentialMetadata,
    //     },
    //     proof::{KeyProofMetadata, ProofType},
    // };
    // use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer};
    // use serde_json::{from_str, json};

    // #[test]
    // fn test_oid4vci_examples() {
    // Examples from: https://github.com/openid/OpenID4VCI/blob/main/1.0/examples/credential_issuer_metadata_sd_jwt_long.json

    // assert_eq!(
    //     CredentialIssuerMetadata {
    //         credential_issuer: "https://credential-issuer.example.com".parse().unwrap(),
    //         authorization_servers: vec!["https://server.example.com".parse().unwrap()],
    //         nonce_endpoint: None,
    //         credential_endpoint: Url::parse("https://credential-issuer.example.com").unwrap(),
    //         deferred_credential_endpoint: Some(
    //             "https://credential-issuer.example.com/deferred_credential"
    //                 .parse()
    //                 .unwrap()
    //         ),
    //         notification_endpoint: None,
    //         credential_response_encryption: Some(CredentialResponseEncryption {
    //             alg_values_supported: vec!["ECDH-ES".to_string()],
    //             enc_values_supported: vec!["A128GCM".to_string()],
    //             encryption_required: false
    //         }),
    //         credential_identifiers_supported: None,
    //         batch_credential_issuance: None,
    //         signed_metadata: None,
    //         display: Some(vec![
    //             json!({
    //                 "name": "Example University",
    //                 "locale": "en-US"
    //             }),
    //             json!({
    //                 "name": "Example Université",
    //                 "locale": "fr-FR"
    //             })
    //         ]),
    //         credential_configurations_supported: vec![(
    //             "UniversityDegreeCredential".to_string(),
    //             CredentialConfigurationsSupportedObject {
    //                 credential_format: CredentialFormats::<WithParameters>::JwtVcJson(Parameters {
    //                     parameters: (jwt_vc_json::CredentialDefinition {
    //                         type_: vec![
    //                             "VerifiableCredential".to_string(),
    //                             "UniversityDegreeCredential".to_string()
    //                         ],
    //                         credential_subject: CredentialSubject {
    //                             credential_subject: None
    //                         }
    //                     })
    //                     .into()
    //                 }),
    //                 scope: Some("UniversityDegree".to_string()),
    //                 cryptographic_binding_methods_supported: vec!["did:example".to_string()],
    //                 credential_signing_alg_values_supported: vec![AlgIdentifier::String("ES256".to_string())],
    //                 proof_types_supported: vec![(
    //                     ProofType::Jwt,
    //                     KeyProofMetadata {
    //                         proof_signing_alg_values_supported: vec!["ES256".to_string()]
    //                     }
    //                 )]
    //                 .into_iter()
    //                 .collect(),
    //                 credential_metadata: Some(CredentialMetadata {
    //                     display: Some(vec![serde_json::from_value(json!({
    //                         "name": "University Credential",
    //                         "locale": "en-US",
    //                         "logo": {
    //                             "uri": "https://university.example.edu/public/logo.png",
    //                             "alt_text": "a square logo of a university"
    //                         },
    //                         "background_color": "#12107c",
    //                         "text_color": "#FFFFFF"
    //                     }))
    //                     .unwrap()]),
    //                     claims: Some(vec![
    //                         ClaimDescription {
    //                             path: ClaimPathPointer::try_new(vec![
    //                                 ClaimPathElement::String("credentialSubject".to_string()),
    //                                 ClaimPathElement::String("given_name".to_string())
    //                             ])
    //                             .unwrap(),
    //                             mandatory: false,
    //                             display: vec![serde_json::from_value(json!({
    //                                 "name": "Given Name",
    //                                 "locale": "en-US"
    //                             }))
    //                             .unwrap()],
    //                         },
    //                         ClaimDescription {
    //                             path: ClaimPathPointer::try_new(vec![
    //                                 ClaimPathElement::String("credentialSubject".to_string()),
    //                                 ClaimPathElement::String("family_name".to_string())
    //                             ])
    //                             .unwrap(),
    //                             mandatory: false,
    //                             display: vec![serde_json::from_value(json!({
    //                                 "name": "Surname",
    //                                 "locale": "en-US"
    //                             }))
    //                             .unwrap()],
    //                         },
    //                         ClaimDescription {
    //                             path: ClaimPathPointer::try_new(vec![
    //                                 ClaimPathElement::String("credentialSubject".to_string()),
    //                                 ClaimPathElement::String("degree".to_string())
    //                             ])
    //                             .unwrap(),
    //                             mandatory: false,
    //                             display: vec![],
    //                         },
    //                         ClaimDescription {
    //                             path: ClaimPathPointer::try_new(vec![
    //                                 ClaimPathElement::String("credentialSubject".to_string()),
    //                                 ClaimPathElement::String("gpa".to_string())
    //                             ])
    //                             .unwrap(),
    //                             mandatory: false,
    //                             display: vec![serde_json::from_value(json!({
    //                                 "name": "GPA",
    //                             }))
    //                             .unwrap()],
    //                         }
    //                     ])
    //                 })
    //             },
    //         ),]
    //         .into_iter()
    //         .collect(),
    //     },
    //     from_str::<CredentialIssuerMetadata>(include_str!(
    //         "../../tests/examples/credential_issuer_metadata_sd_jwt_long.json"
    //     ))
    //     .unwrap()
    // );

    #[test]
    fn test_deserialize_with_invalid_entry() {
        // The second entry is invalid because it lacks the `credential_definition` field.
        let json_data = serde_json::json!(
            {
                "credential_issuer": "https://credential-issuer.example.org",
                "credential_endpoint": "https://credential-issuer.example.org",
                "credential_configurations_supported": {
                    "ValidCredential": {
                        "format": "jwt_vc_json",
                        "credential_definition":{
                            "type": [
                                "VerifiableCredential"
                            ]
                        }
                    },
                    "InvalidCredential": {
                        "format": "jwt_vc_json",
                    }
                }
            }
        );

        // Deserialize the JSON data into the CredentialIssuerMetadata struct.
        let credential_issuer_metadata: CredentialIssuerMetadata = serde_json::from_value(json_data).unwrap();

        // Check that only the valid entry is present in the resulting map.
        assert!(credential_issuer_metadata
            .credential_configurations_supported
            .contains_key("ValidCredential"));

        // Check that the invalid entry has been filtered out.
        assert!(!credential_issuer_metadata
            .credential_configurations_supported
            .contains_key("InvalidCredential"));
    }
}
