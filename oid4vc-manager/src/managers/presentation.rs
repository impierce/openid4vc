use anyhow::Result;
use oid4vp::{
    evaluate_input, ClaimFormatDesignation, InputDescriptorMappingObject, PathNested, PresentationDefinition,
    PresentationSubmission,
};

/// Takes a [`PresentationDefinition`] and a credential and creates a [`PresentationSubmission`] from it if the
/// credential meets the requirements.
// TODO: make VP/VC format agnostic. In current form only jwt_vp_json + jwt_vc_json are supported. Also, make sure that
// an error is returned if the credentials do not meet the requirements in the `PresentationDefinition`.
pub fn create_presentation_submission(
    id: String,
    presentation_definition: &PresentationDefinition,
    credentials: &[serde_json::Value],
) -> Result<PresentationSubmission> {
    let definition_id = presentation_definition.id().clone();
    let descriptor_map = presentation_definition
        .input_descriptors()
        .iter()
        .enumerate()
        .filter_map(|(index, input_descriptor)| {
            credentials.iter().find_map(|credential| {
                evaluate_input(input_descriptor, credential).then_some(InputDescriptorMappingObject {
                    id: input_descriptor.id().clone(),
                    format: ClaimFormatDesignation::JwtVpJson,
                    path: "$".to_string(),
                    path_nested: Some(PathNested {
                        id: None,
                        path: format!("$.vp.verifiableCredential[{}]", index),
                        format: ClaimFormatDesignation::JwtVcJson,
                        path_nested: None,
                    }),
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(PresentationSubmission {
        id,
        definition_id,
        descriptor_map,
    })
}

// Creates a `PresentationSubmission` for a dc+sd-jwt presentation.
// TODO:remove this function and make sure that `create_presentation_submission` can generate submissions regardless of
// the VP/VC format.
pub fn create_sd_jwt_presentation_submission(
    id: String,
    presentation_definition: &PresentationDefinition,
    credentials: &[serde_json::Value],
) -> Result<PresentationSubmission> {
    let definition_id = presentation_definition.id().clone();
    let descriptor_map = presentation_definition
        .input_descriptors()
        .iter()
        .filter_map(|input_descriptor| {
            credentials.iter().find_map(|credential| {
                evaluate_input(input_descriptor, credential).then_some(InputDescriptorMappingObject {
                    id: input_descriptor.id().clone(),
                    format: ClaimFormatDesignation::DcSdJwt,
                    path: "$".to_string(),
                    path_nested: None,
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(PresentationSubmission {
        id,
        definition_id,
        descriptor_map,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_create_presentation_submission() {
        // With example data from:
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html#name-vc-signed-as-a-jwt-not-usin

        let presentation_definition: PresentationDefinition = serde_json::from_value(json!(
            {
                "id": "example_jwt_vc",
                "input_descriptors": [
                    {
                        "id": "id_credential",
                        "format": {
                            "jwt_vc_json": {
                                "proof_type": [
                                    "JsonWebSignature2020"
                                ]
                            }
                        },
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.vc.type"
                                    ],
                                    "filter": {
                                        "type": "array",
                                        "contains": {
                                            "const": "IDCredential"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        ))
        .unwrap();

        let credential_data = json!(
            {
                "iss": "https://example.gov/issuers/565049",
                "nbf": 1262304000,
                "jti": "http://example.gov/credentials/3732",
                "sub": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "vc": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "IDCredential"
                    ],
                    "credentialSubject": {
                        "given_name": "Max",
                        "family_name": "Mustermann",
                        "birthdate": "1998-01-11",
                        "address": {
                            "street_address": "Sandanger 25",
                            "locality": "Musterstadt",
                            "postal_code": "123456",
                            "country": "DE"
                        }
                    }
                }
            }
        );

        let presentation_submission = create_presentation_submission(
            "example_jwt_vc_presentation_submission".to_string(),
            &presentation_definition,
            &[credential_data],
        )
        .unwrap();

        assert_eq!(
            json!(presentation_submission),
            json!(
                {
                    "definition_id": "example_jwt_vc",
                    "id": "example_jwt_vc_presentation_submission",
                    "descriptor_map": [
                        {
                            "id": "id_credential",
                            "path": "$",
                            "format": "jwt_vp_json",
                            "path_nested": {
                                "path": "$.vp.verifiableCredential[0]",
                                "format": "jwt_vc_json"
                            }
                        }
                    ]
                }
            )
        )
    }

    #[test]
    fn test_create_sd_jwt_presentation_submission() {
        // With example data from:
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html#name-ietf-sd-jwt-vc

        let presentation_definition: PresentationDefinition = serde_json::from_value(json!(
            {
                "id": "example_sd_jwt_vc_request",
                "input_descriptors": [
                    {
                        "id": "identity_credential",
                        "format": {
                            "dc+sd-jwt": {
                                "sd-jwt_alg_values": [
                                    "ES256",
                                    "ES384"
                                ],
                                "kb-jwt_alg_values": [
                                    "ES256",
                                    "ES384"
                                ]
                            }
                        },
                        "constraints": {
                            "limit_disclosure": "required",
                            "fields": [
                                {
                                    "path": [
                                        "$.vct"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "const": "pid_dc+sd-jwt"
                                    }
                                },
                                {
                                    "path": [
                                        "$.family_name"
                                    ]
                                },
                                {
                                    "path": [
                                        "$.given_name"
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        ))
        .unwrap();

        let credential_data = json!(
            {
                "sub": "did:jwk:eyJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJraWQiOiJFRUdOOGViWjlxVGRIRlJYSjFwRG1fM25iMllLSk1fWU9sV2QzRG44Z0lNIiwia3R5IjoiT0tQIiwieCI6Ik4tMkgtZlJ1RmlHQy1ON05ET0Zob214T01ZWnVWd29nZF9hYV81S0h1aUkifQ",
                "id": "urn:uuid:730d0750-d418-430a-85bd-2faca00f2447",
                "iss": "did:example:123",
                "nbf": 1741094882,
                "exp": 1772630882,
                "vct": "pid_dc+sd-jwt",
                "iat": 1741094882,
                "family_name": "Ferris",
                "given_name": "Crabman"
            }
        );

        let presentation_submission = create_sd_jwt_presentation_submission(
            "example_sd_jwt_vc_presentation_submission".to_string(),
            &presentation_definition,
            &[credential_data],
        )
        .unwrap();

        assert_eq!(
            json!(presentation_submission),
            json!(
                {
                    "definition_id": "example_sd_jwt_vc_request",
                    "id": "example_sd_jwt_vc_presentation_submission",
                    "descriptor_map": [
                        {
                            "id": "identity_credential",
                            "path": "$",
                            "format": "dc+sd-jwt"
                        }
                    ]
                }
            )
        )
    }
}
