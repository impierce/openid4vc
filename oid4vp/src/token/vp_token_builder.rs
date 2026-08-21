use crate::dcql::dcql_query::{CredentialQuery, CredentialQueryId, DcqlQuery};
use crate::token::vp_token::{Presentations, VpToken};
use anyhow::Result;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpTokenBuilderError {
    #[error("Required credential set not satisfied: {0:?}")]
    RequiredCredentialSetNotSatisfied(crate::dcql::dcql_query::CredentialSetQuery),
    #[error("Missing required credential: {0}")]
    MissingRequiredCredential(CredentialQueryId),
    #[error("Unrequested credential: {0}")]
    UnrequestedCredential(CredentialQueryId),
    #[error("Multiple presentations not allowed for credential: {0}")]
    MultipleNotAllowed(CredentialQueryId),
}

#[derive(Default)]
pub struct VpTokenBuilder {
    presentations: HashMap<CredentialQueryId, Presentations>,
    dcql_query: Option<DcqlQuery>,
}

impl VpTokenBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder_dcql_query(dcql_query: DcqlQuery) -> Self {
        Self {
            presentations: HashMap::new(),
            dcql_query: Some(dcql_query),
        }
    }

    // for multiple presentations for the same credential_id
    pub fn add_presentations(mut self, credential_id: CredentialQueryId, presentations: Presentations) -> Self {
        self.presentations.insert(credential_id, presentations);
        self
    }

    pub fn build(self) -> Result<VpToken, VpTokenBuilderError> {
        tracing::debug!(
            presentation_count = self.presentations.len(),
            has_dcql = self.dcql_query.is_some(),
            "Building VP Token"
        );
        if let Some(ref dcql_query) = self.dcql_query {
            self.validate_against_dcql(dcql_query)?;
        }

        Ok(VpToken {
            presentations: self.presentations,
        })
    }

    /// Validate the presentations against the DCQL query's requirements (credential sets, multiple constraints, unrequested credentials).
    fn validate_against_dcql(&self, dcql_query: &DcqlQuery) -> Result<(), VpTokenBuilderError> {
        validate_presentation_submission(&self.presentations, dcql_query)
    }
}

/// Validates that the provided map of presentations satisfies the structural requirements
/// of the DCQL query (required sets, multiple constraints, unrequested credentials).
#[tracing::instrument(level = "debug", err, skip(presentations, dcql_query))]
pub fn validate_presentation_submission(
    presentations: &HashMap<CredentialQueryId, Presentations>,
    dcql_query: &DcqlQuery,
) -> Result<(), VpTokenBuilderError> {
    tracing::debug!(
        presentation_count = presentations.len(),
        query_count = dcql_query.credentials.len(),
        "Validating presentation submission against DCQL query"
    );
    let credential_queries: HashMap<CredentialQueryId, &CredentialQuery> =
        dcql_query.credentials.iter().map(|cq| (cq.id.clone(), cq)).collect();

    if let Some(credential_sets) = &dcql_query.credential_sets {
        // Check if all required credential sets are satisfied.
        for credential_set in credential_sets {
            if credential_set.required.unwrap_or(true) && !is_credential_set_satisfied(presentations, credential_set) {
                return Err(VpTokenBuilderError::RequiredCredentialSetNotSatisfied(
                    credential_set.clone(),
                ));
            }
        }
    } else {
        // If there are no credential sets, we assume all credentials are required.
        for credential_query in &dcql_query.credentials {
            if !presentations.contains_key(&credential_query.id) {
                return Err(VpTokenBuilderError::MissingRequiredCredential(
                    credential_query.id.clone(),
                ));
            }
        }
    }

    // Check multiple constraints and for no unrequested presentations
    for (credential_id, credential_presentations) in presentations {
        if let Some(credential_query) = credential_queries.get(credential_id) {
            if !credential_query.multiple.unwrap_or(false) && credential_presentations.len() > 1 {
                return Err(VpTokenBuilderError::MultipleNotAllowed(credential_id.clone()));
            }
        } else {
            return Err(VpTokenBuilderError::UnrequestedCredential(credential_id.clone()));
        }
    }

    Ok(())
}

/// Check if at least one option in the credential set is fully satisfied
fn is_credential_set_satisfied(
    presentations: &HashMap<CredentialQueryId, Presentations>,
    credential_set: &crate::dcql::dcql_query::CredentialSetQuery,
) -> bool {
    credential_set.options.iter().any(|option| {
        option
            .iter()
            .all(|credential_query_id| presentations.contains_key(credential_query_id))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcql::dcql_query::CredentialQueryId;
    use serde_json::json;

    fn dummy_presentation() -> String {
        "dummy.jwt.token".to_string()
    }

    #[test]
    fn test_vp_token_builder_unrequested_credential() {
        let dcql_query_json = json!({
            "credentials": [
                {
                    "id": "requested-cred",
                    "format": "dc+sd-jwt",
                    "meta": {
                        "vct_values": ["https://example.com/cred"]
                    },
                    "claims": []
                }
            ]
        });

        let dcql_query: DcqlQuery = serde_json::from_value(dcql_query_json).unwrap();

        // Test: Add presentation for credential that wasn't requested
        let result = VpTokenBuilder::builder_dcql_query(dcql_query)
            .add_presentations(
                CredentialQueryId::try_new("requested-cred").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .add_presentations(
                CredentialQueryId::try_new("unrequested-cred").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .build();

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VpTokenBuilderError::UnrequestedCredential(_)
        ));
    }

    #[test]
    fn test_vp_token_builder_optional_credential_set() {
        let dcql_query_json = json!({
            "credentials": [
                {
                    "id": "mdl-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": []
                },
                {
                    "id": "optional-cred",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.example"
                    },
                    "claims": []
                }
            ],
            "credential_sets": [
                {
                // required omitted is the same as "required: true"

                    "options": [["mdl-id"]]
                },
                {
                    "required": false,
                    "options": [["optional-cred"]]
                }
            ]
        });

        let dcql_query: DcqlQuery = serde_json::from_value(dcql_query_json).unwrap();

        // Provide only required credential, skip optional (should pass)
        let result = VpTokenBuilder::builder_dcql_query(dcql_query)
            .add_presentations(
                CredentialQueryId::try_new("mdl-id").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn test_vp_token_builder_missing_required_credential_set() {
        let dcql_query_json = json!({
            "credentials": [
                {
                    "id": "mdl-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": []
                },
                {
                    "id": "optional-cred",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.example"
                    },
                    "claims": []
                }
            ],
            "credential_sets": [
                {
                    "required": true,
                    "options": [["mdl-id"]]
                },
                {
                    // This credential set is required, but not in the presentations so should cause an error.
                    "required": true,
                    "options": [["optional-cred"]]
                }
            ]
        });

        let dcql_query: DcqlQuery = serde_json::from_value(dcql_query_json).unwrap();

        let result = VpTokenBuilder::builder_dcql_query(dcql_query)
            .add_presentations(
                CredentialQueryId::try_new("mdl-id").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .add_presentations(
                // This credential is unrequested and should cause an error
                CredentialQueryId::try_new("thats-not-right").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .build();

        if let Err(ref err) = result {
            println!("Error: {}", err);
        }
        assert!(result.is_err());
    }

    #[test]
    fn test_vp_token_builder_credential_sets_not_required() {
        let dcql_query_json = json!({
            "credentials": [
                {
                    "id": "mdl-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": []
                },
                {
                    "id": "optional-cred",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.example"
                    },
                    "claims": []
                }
            ],
            "credential_sets": [
                {
                    "required": false,
                    "options": [["mdl-id"]]
                },
                {
                    "required": false,
                    "options": [["optional-cred"]]
                }
            ]
        });

        let dcql_query: DcqlQuery = serde_json::from_value(dcql_query_json).unwrap();

        let result = VpTokenBuilder::builder_dcql_query(dcql_query)
            .add_presentations(
                CredentialQueryId::try_new("mdl-id").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .add_presentations(
                CredentialQueryId::try_new("optional-cred").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .build();

        println!("Result: {:#?}", result);

        if let Err(ref err) = result {
            println!("Error: {}", err);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_vp_token_builder_empty_presentations_with_credential_sets_not_required() {
        let dcql_query_json = json!({
            "credentials": [
                {
                    "id": "mdl-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": []
                },
                {
                    "id": "optional-cred",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.example"
                    },
                    "claims": []
                }
            ],
            "credential_sets": [
                {
                    "required": false,
                    "options": [["mdl-id"]]
                },
                {
                    "required": false,
                    "options": [["optional-cred"]]
                }
            ]
        });

        let dcql_query: DcqlQuery = serde_json::from_value(dcql_query_json).unwrap();

        let result = VpTokenBuilder::builder_dcql_query(dcql_query).build();

        println!("Result: {:#?}", result);

        if let Err(ref err) = result {
            println!("Error: {}", err);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_vp_token_builder_credential_sets_not_required_unrequested_credential() {
        let dcql_query_json = json!({
            "credentials": [
                {
                    "id": "mdl-id",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                    },
                    "claims": []
                },
                {
                    "id": "optional-cred",
                    "format": "mso_mdoc",
                    "meta": {
                        "doctype_value": "org.iso.example"
                    },
                    "claims": []
                }
            ],
            "credential_sets": [
                {
                    "required": false,
                    "options": [["mdl-id"]]
                },
                {
                    "required": false,
                    "options": [["optional-cred"]]
                }
            ]
        });

        let dcql_query: DcqlQuery = serde_json::from_value(dcql_query_json).unwrap();

        let result = VpTokenBuilder::builder_dcql_query(dcql_query)
            .add_presentations(
                CredentialQueryId::try_new("unrequested-cred").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .add_presentations(
                CredentialQueryId::try_new("optional-cred").unwrap(),
                Presentations::try_new(vec![dummy_presentation().into()]).unwrap(),
            )
            .build();

        println!("Result: {:#?}", result);

        if let Err(ref err) = result {
            println!("Error: {}", err);
        }
        assert!(result.is_err());
    }
}
