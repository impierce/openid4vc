use crate::dcql::dcql_query::{CredentialQuery, CredentialQueryId, DcqlQuery};
use crate::token::vp_token::{PresentationFormat, VpToken};
use anyhow::Result;
use std::collections::HashMap;
use validator::{Validate, ValidationError, ValidationErrors};

#[derive(Default, Validate)]
pub struct VpTokenBuilder {
    presentations: HashMap<CredentialQueryId, Vec<PresentationFormat>>,
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

    pub fn add_presentation(mut self, credential_id: CredentialQueryId, presentation: PresentationFormat) -> Self {
        self.presentations.entry(credential_id).or_default().push(presentation);
        self
    }

    // for multiple presentations for the same credential_id
    pub fn add_presentations(
        mut self,
        credential_id: CredentialQueryId,
        presentations: Vec<PresentationFormat>,
    ) -> Self {
        self.presentations.insert(credential_id, presentations);
        self
    }

    pub fn build(self) -> Result<VpToken, ValidationErrors> {
        self.validate()?;
        if let Some(ref dcql_query) = self.dcql_query {
            dcql_query.validate()?;
            self.validate_against_dcql(dcql_query)?;
        }

        Ok(VpToken {
            presentations: self.presentations,
        })
    }

    // Validate the VpToken against the provided DcqlQuery.
    fn validate_against_dcql(&self, dcql_query: &DcqlQuery) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        let credential_queries: HashMap<CredentialQueryId, &CredentialQuery> =
            dcql_query.credentials.iter().map(|cq| (cq.id.clone(), cq)).collect();

        if let Some(credential_sets) = &dcql_query.credential_sets {
            // Check if all required credential sets are satisfied.
            for credential_set in credential_sets {
                if credential_set.required.unwrap_or(true) && !self.is_credential_set_satisfied(credential_set) {
                    errors.add(
                        "credential_sets",
                        ValidationError::new("required_credential_set_not_satisfied"),
                    );
                }
            }
        } else {
            // If there are no credential sets, we assume all credentials are required.
            for credential_query in &dcql_query.credentials {
                if !self.presentations.contains_key(&credential_query.id) {
                    errors.add("presentations", ValidationError::new("missing_required_credential"));
                }
            }
        }
        // Check multiple constraints and for no unrequested presentations
        for (credential_id, presentations) in &self.presentations {
            if let Some(credential_query) = credential_queries.get(credential_id) {
                if !credential_query.multiple.unwrap_or(false) && presentations.len() > 1 {
                    errors.add("presentations", ValidationError::new("multiple_not_allowed"));
                }
            } else {
                errors.add("presentations", ValidationError::new("unrequested_credential"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if at least one option in the credential set is fully satisfied
    fn is_credential_set_satisfied(&self, credential_set: &crate::dcql::dcql_query::CredentialSetQuery) -> bool {
        credential_set.options.iter().any(|option| {
            option.iter().all(|credential_id_str| {
                crate::dcql::dcql_query::CredentialQueryId::try_new(credential_id_str.clone())
                    .map(|id| self.presentations.contains_key(&id))
                    .unwrap_or(false)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcql::dcql_query::CredentialQueryId;
    use serde_json::json;

    fn dummy_presentation() -> PresentationFormat {
        PresentationFormat::JwtVcJson("dummy.jwt.token".to_string())
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
            .add_presentation(
                CredentialQueryId::try_new("unrequested-cred".to_string()).unwrap(),
                dummy_presentation(),
            )
            .build();

        assert!(result.is_err());
        let error_string = result.unwrap_err().to_string();
        assert!(error_string.contains("unrequested_credential"));
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
            .add_presentation(
                CredentialQueryId::try_new("mdl-id".to_string()).unwrap(),
                dummy_presentation(),
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
            .add_presentation(
                CredentialQueryId::try_new("mdl-id".to_string()).unwrap(),
                dummy_presentation(),
            )
            .add_presentation(
                // This credential is unrequested and should cause an error
                CredentialQueryId::try_new("thats-not-right".to_string()).unwrap(),
                dummy_presentation(),
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
            .add_presentation(
                CredentialQueryId::try_new("mdl-id".to_string()).unwrap(),
                dummy_presentation(),
            )
            .add_presentation(
                CredentialQueryId::try_new("optional-cred".to_string()).unwrap(),
                dummy_presentation(),
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
            .add_presentation(
                CredentialQueryId::try_new("unrequested-cred".to_string()).unwrap(),
                dummy_presentation(),
            )
            .add_presentation(
                CredentialQueryId::try_new("optional-cred".to_string()).unwrap(),
                dummy_presentation(),
            )
            .build();

        println!("Result: {:#?}", result);

        if let Err(ref err) = result {
            println!("Error: {}", err);
        }
        assert!(result.is_err());
    }
}
