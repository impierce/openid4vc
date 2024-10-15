use anyhow::Result;
use oid4vp::{
    evaluate_input, ClaimFormatDesignation, InputDescriptorMappingObject, PathNested, PresentationDefinition,
    PresentationSubmission,
};

/// Takes a [`PresentationDefinition`] and a credential and creates a [`PresentationSubmission`] from it if the
/// credential meets the requirements.
// TODO: make VP/VC format agnostic. In current form only jwt_vp_json + jwt_vc_json are supported.
pub fn create_presentation_submission(
    presentation_definition: &PresentationDefinition,
    credentials: &[serde_json::Value],
) -> Result<PresentationSubmission> {
    let id = "Submission ID".to_string();
    let definition_id = presentation_definition.id().clone();
    let descriptor_map = presentation_definition
        .input_descriptors()
        .iter()
        .enumerate()
        .map(|(index, input_descriptor)| {
            credentials
                .iter()
                .find_map(|credential| {
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
                .unwrap()
        })
        .collect::<Vec<_>>();
    Ok(PresentationSubmission {
        id,
        definition_id,
        descriptor_map,
    })
}

pub fn create_sd_jwt_presentation_submission(
    presentation_definition: &PresentationDefinition,
    credentials: &[serde_json::Value],
) -> Result<PresentationSubmission> {
    let id = "Submission ID".to_string();
    let definition_id = presentation_definition.id().clone();
    let descriptor_map = presentation_definition
        .input_descriptors()
        .iter()
        .enumerate()
        .map(|(_index, input_descriptor)| {
            credentials
                .iter()
                .find_map(|credential| {
                    evaluate_input(input_descriptor, credential).then_some(InputDescriptorMappingObject {
                        id: input_descriptor.id().clone(),
                        format: ClaimFormatDesignation::VcSdJwt,
                        path: "$".to_string(),
                        path_nested: None,
                    })
                })
                .unwrap()
        })
        .collect::<Vec<_>>();
    Ok(PresentationSubmission {
        id,
        definition_id,
        descriptor_map,
    })
}

#[test]
fn test() {
    let sd_jwt_vc = serde_json::json!({
      "_sd": [
        "3oUCnaKt7wqDKuyh-LgQozzfhgb8gO5Ni-RCWsWW2vA",
        "8z8z9X9jUtb99gjejCwFAGz4aqlHf-sCqQ6eM_qmpUQ",
        "Cxq4872UXXngGULT_kl8fdwVFkyK6AJfPZLy7L5_0kI",
        "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
        "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
        "sFcViHN-JG3eTUyBmU4fkwusy5I1SLBhe1jNvKxP5xM",
        "tiTngp9_jhC389UP8_k67MXqoSfiHq3iK6o9un4we_Y",
        "xsKkGJXD1-e3I9zj0YyKNv-lU5YqhsEAF9NhOr8xga4"
      ],
      "iss": "https://example.com/issuer",
      "iat": 1683000000,
      "exp": 1883000000,
      "vct": "https://credentials.example.com/identity_credential",
      "given_name": "John",
      "family_name": "Doe",
      "birthdate": "1940-01-01",
      "_sd_alg": "sha-256",
      "cnf": {
        "jwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
          "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        }
      }
    });

    let presentation_definition: PresentationDefinition = serde_json::from_value(serde_json::json!({
      "id": "example_sd_jwt_vc_request",
      "input_descriptors": [
        {
          "id": "identity_credential",
          "format": {
            "vc+sd-jwt": {
              "sd-jwt_alg_values": ["ES256", "ES384"],
              "kb-jwt_alg_values": ["ES256", "ES384"]
            }
          },
          "constraints": {
            "limit_disclosure": "required",
            "fields": [
              {
                "path": ["$.vct"],
                "filter": {
                  "type": "string",
                  "const": "https://credentials.example.com/identity_credential"
                }
              },
              {
                "path": ["$.family_name"]
              },
              {
                "path": ["$.given_name"]
              }
            ]
          }
        }
      ]
    }))
    .unwrap();

    let res = create_sd_jwt_presentation_submission(&presentation_definition, &[sd_jwt_vc]).unwrap();

    println!("{}", serde_json::to_string_pretty(&res).unwrap());

    let jwt_vc_json = serde_json::json!({
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
    });

    let presentation_definition2: PresentationDefinition = serde_json::from_value(serde_json::json!({
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
    }))
    .unwrap();

    let res2 = create_presentation_submission(&presentation_definition2, &[jwt_vc_json]).unwrap();

    println!("{}", serde_json::to_string_pretty(&res2).unwrap());

    let res3 = merge_submissions(vec![res, res2]);

    println!("HHHEEREERREEREE\n{}", serde_json::to_string_pretty(&res3).unwrap());
}

pub fn merge_submissions(submissions: Vec<PresentationSubmission>) -> PresentationSubmission {
    let id = "Submission ID".to_string();
    let definition_id = "Submission ID".to_string();

    let descriptor_map = submissions
        .into_iter()
        .flat_map(|submission| submission.descriptor_map)
        .collect::<Vec<_>>();

    let descriptor_map = descriptor_map
        .into_iter()
        .enumerate()
        .map(|(index, mut descriptor)| {
            descriptor.path = format!("[{index}]");
            descriptor
        })
        .collect();

    PresentationSubmission {
        id,
        definition_id,
        descriptor_map,
    }
}

// let descriptor_map: Vec<_> = submission_1
// .descriptor_map
// .iter()
// .chain(submission_2.descriptor_map.iter())
// .cloned()
// .collect::<Vec<_>>();

// let descriptor_map = descriptor_map
// .into_iter()
// .enumerate()
// .map(|(index, mut descriptor)| {
//     descriptor.path = format!("[{index}]");
//     descriptor
// })
// .collect();

// PresentationSubmission {
// id,
// definition_id,
// descriptor_map,
// }
