use anyhow::Result;
use oid4vp::{
    evaluate_input, ClaimFormatDesignation, InputDescriptorMappingObject, PathNested, PresentationDefinition,
    PresentationSubmission,
};

/// Takes a [`PresentationDefinition`] and a credential and creates a [`PresentationSubmission`] from it if the
/// credential meets the requirements.
// TODO: make VP/VC fromat agnostic. In current form only jwt_vp_json + jwt_vc_json are supported.
pub fn create_presentation_submission(
    presentation_definition: &PresentationDefinition,
    credentials: Vec<serde_json::Value>,
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
