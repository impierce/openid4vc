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
        .filter_map(|(_index, input_descriptor)| {
            credentials.iter().find_map(|credential| {
                evaluate_input(input_descriptor, credential).then_some(InputDescriptorMappingObject {
                    id: input_descriptor.id().clone(),
                    format: ClaimFormatDesignation::VcSdJwt,
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
