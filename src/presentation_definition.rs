use serde::Deserialize;
use std::collections::HashMap;

/// As specified in https://identity.foundation/presentation-exchange/#presentation-definition.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct PresentationDefinition {
    id: String,
    input_descriptors: Vec<InputDescriptor>,
    name: Option<String>,
    purpose: Option<String>,
    #[serde(flatten)]
    format: Option<HashMap<String, ClaimFormatDesignation>>,
    submission_requirements: Option<String>,
}

/// As specified in https://identity.foundation/presentation-exchange/#input-descriptor-object.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct InputDescriptor {
    id: String,
    name: Option<String>,
    purpose: Option<String>,
    #[serde(flatten)]
    format: Option<HashMap<String, ClaimFormatDesignation>>,
    constraints: Constraints,
    group: Option<String>,
    schema: Option<String>,
}

/// TODO: fix camelcase problem.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub enum ClaimFormatDesignation {
    alg(Option<String>),
    proof_type(Option<String>),
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Constraints {
    fields: Option<Vec<Field>>,
    limit_disclosure: Option<String>,
}

// TODO: Should use https://docs.rs/jsonpath_lib/0.3.0/jsonpath_lib/?
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Field {
    path: Vec<String>,
    id: Option<String>,
    purpose: Option<String>,
    name: Option<String>,
    filter: Option<Filter>,
    optional: Option<bool>,
}

// TODO: Find solution for JSONSchema.
#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Filter {
    const_: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize() {
        let input = "presentation_definition=%7B%22format%22+%3A+null%2C+%22id%22+%3A+%221%22%2C+%22input_descriptors%22+%3A+%5B%7B%22constraints%22+%3A+%7B%22fields%22+%3A+%5B%7B%22filter%22+%3A+%7B%22const%22%3A+%22VerifiableId%22%7D%2C+%22id%22+%3A+null%2C+%22path%22+%3A+%5B%22%24.type%22%5D%2C+%22purpose%22+%3A+null%7D%5D%7D%2C+%22format%22+%3A+null%2C+%22group%22+%3A+null%2C+%22id%22+%3A+%221%22%2C+%22name%22+%3A+null%2C+%22purpose%22+%3A+null%2C+%22schema%22+%3A+null%7D%5D%2C+%22name%22+%3A+null%2C+%22purpose%22+%3A+null%2C+%22submission_requirements%22+%3A+null%7D";
        let decoded = url::form_urlencoded::parse(input.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect::<HashMap<String, String>>();

        let presentation_definition: PresentationDefinition =
            serde_json::from_str(&decoded["presentation_definition"]).unwrap();
        dbg!(&presentation_definition);
    }

    
}
