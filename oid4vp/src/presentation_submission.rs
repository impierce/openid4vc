use crate::presentation_definition::ClaimFormatDesignation;
use serde::{Deserialize, Serialize};

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[derive(Deserialize, Debug, Serialize)]
pub struct PresentationSubmission {
    // TODO: Must be unique.
    id: String,
    // TODO: Value must be the id value of a valid presentation definition.
    definition_id: String,
    descriptor_map: Vec<InputDescriptorMappingObject>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug, Serialize)]
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
    path_nested: Option<Box<Self>>,
}
