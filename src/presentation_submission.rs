use serde::Deserialize;
use std::collections::HashMap;

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct PresentationDefinition {
    // TODO: Must be unique.
    id: String,
    // TODO: Value must be the id value of a valid presentation definition.
    definition_id: String,
    descriptor_map: Vec<InputDescriptorMap>,
}

#[derive(Deserialize, Debug)]
pub struct InputDescriptorMap {
    id: String,
    format: String,
    // TODO Must be a JSONPath string expression
    path: String,
    // TODO: `path_nested`
}
