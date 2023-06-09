use crate::presentation_definition::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Serialize, PartialEq)]
pub struct PresentationSubmission {
    // TODO: Must be unique.
    id: String,
    // TODO: Value must be the id value of a valid presentation definition.
    definition_id: String,
    descriptor_map: Vec<InputDescriptorMappingObject>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Serialize, PartialEq)]
pub struct InputDescriptorMappingObject {
    // Matches the `id` property of the Input Descriptor in the Presentation Definition that this Presentation
    // Submission is related to.
    id: String,
    // Matches one of the Claim Format Designation. This denotes the data format of the Claim.
    format: ClaimFormatDesignation,
    // TODO Must be a JSONPath string expression
    // Indicates the Claim submitted in relateion to the identified Input Descriptor, When executed against the
    // top-level of the object the Presentation Submission is embedded within.
    path: String,
    path_nested: Option<PathNested>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Serialize, PartialEq)]
pub struct PathNested {
    id: Option<String>,
    format: ClaimFormatDesignation,
    path: String,
    path_nested: Option<Box<Self>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
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
    fn test_deserialize_presentation_submission() {
        assert_eq!(
            PresentationSubmission {
                id: "Presentation example 2".to_string(),
                definition_id: "Example with multiple VPs".to_string(),
                descriptor_map: vec![
                    InputDescriptorMappingObject {
                        id: "ID Card with constraints".to_string(),
                        format: ClaimFormatDesignation::LdpVp,
                        path: "$[0]".to_string(),
                        path_nested: Some(PathNested {
                            format: ClaimFormatDesignation::LdpVc,
                            path: "$[0].verifiableCredential[0]".to_string(),
                            id: None,
                            path_nested: None
                        })
                    },
                    InputDescriptorMappingObject {
                        id: "Ontario Health Insurance Plan".to_string(),
                        format: ClaimFormatDesignation::JwtVpJson,
                        path: "$[1]".to_string(),
                        path_nested: Some(PathNested {
                            format: ClaimFormatDesignation::JwtVcJson,
                            path: "$[1].vp.verifiableCredential[0]".to_string(),
                            id: None,
                            path_nested: None
                        })
                    }
                ]
            },
            json_example::<PresentationSubmission>(
                "../oid4vp/tests/examples/response/presentation_submission_multiple_vps.json"
            )
        );

        assert_eq!(
            PresentationSubmission {
                id: "Presentation example 1".to_string(),
                definition_id: "Example with selective disclosure".to_string(),
                descriptor_map: vec![InputDescriptorMappingObject {
                    id: "ID card with constraints".to_string(),
                    format: ClaimFormatDesignation::LdpVp,
                    path: "$".to_string(),
                    path_nested: Some(PathNested {
                        format: ClaimFormatDesignation::LdpVc,
                        path: "$.verifiableCredential[0]".to_string(),
                        id: None,
                        path_nested: None
                    })
                }]
            },
            json_example::<PresentationSubmission>("../oid4vp/tests/examples/response/presentation_submission.json")
        );

        assert_eq!(
            PresentationSubmission {
                definition_id: "example_vc_ac_sd".to_string(),
                id: "example_vc_ac_sd_presentation_submission".to_string(),
                descriptor_map: vec![InputDescriptorMappingObject {
                    id: "id_credential".to_string(),
                    path: "$".to_string(),
                    format: ClaimFormatDesignation::AcVp,
                    path_nested: Some(PathNested {
                        path: "$.requested_proof.revealed_attr_groups.id_card_credential".to_string(),
                        format: ClaimFormatDesignation::AcVc,
                        id: None,
                        path_nested: None
                    })
                }]
            },
            json_example::<PresentationSubmission>("../oid4vp/tests/examples/response/ps_ac_vc_sd.json")
        );

        assert_eq!(
            PresentationSubmission {
                definition_id: "example_jwt_vc".to_string(),
                id: "example_jwt_vc_presentation_submission".to_string(),
                descriptor_map: vec![InputDescriptorMappingObject {
                    id: "id_credential".to_string(),
                    path: "$".to_string(),
                    format: ClaimFormatDesignation::JwtVpJson,
                    path_nested: Some(PathNested {
                        path: "$.vp.verifiableCredential[0]".to_string(),
                        format: ClaimFormatDesignation::JwtVcJson,
                        id: None,
                        path_nested: None
                    })
                }]
            },
            json_example::<PresentationSubmission>("../oid4vp/tests/examples/response/ps_jwt_vc.json")
        );

        assert_eq!(
            PresentationSubmission {
                definition_id: "example_ldp_vc".to_string(),
                id: "example_ldp_vc_presentation_submission".to_string(),
                descriptor_map: vec![InputDescriptorMappingObject {
                    id: "id_credential".to_string(),
                    path: "$".to_string(),
                    format: ClaimFormatDesignation::LdpVp,
                    path_nested: Some(PathNested {
                        format: ClaimFormatDesignation::LdpVc,
                        path: "$.verifiableCredential[0]".to_string(),
                        id: None,
                        path_nested: None
                    })
                }]
            },
            json_example::<PresentationSubmission>("../oid4vp/tests/examples/response/ps_ldp_vc.json")
        );

        assert_eq!(
            PresentationSubmission {
                definition_id: "mDL-sample-req".to_string(),
                id: "mDL-sample-res".to_string(),
                descriptor_map: vec![InputDescriptorMappingObject {
                    id: "mDL".to_string(),
                    path: "$".to_string(),
                    format: ClaimFormatDesignation::MsoMdoc,
                    path_nested: None
                }]
            },
            json_example::<PresentationSubmission>("../oid4vp/tests/examples/response/ps_mdl_iso_cbor.json")
        );
    }
}
