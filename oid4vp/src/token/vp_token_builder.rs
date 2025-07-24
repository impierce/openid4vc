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

    /// for multiple presentations for the same credential_id
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

    fn validate_against_dcql(&self, dcql_query: &DcqlQuery) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        let credential_queries: HashMap<CredentialQueryId, &CredentialQuery> =
            dcql_query.credentials.iter().map(|cq| (cq.id.clone(), cq)).collect();

        // Check to see if all required credentials are present.
        for credential_query in &dcql_query.credentials {
            if !self.presentations.contains_key(&credential_query.id) {
                let mut error = ValidationError::new("missing_required_credential");
                error.message = Some(
                    format!(
                        "Required credential '{}' is missing from presentations",
                        credential_query.id
                    )
                    .into(),
                );
                errors.add("presentations", error);
            }
        }

        // Make sure there are no extra or unnecessary presentations
        for credential_id in self.presentations.keys() {
            if !credential_queries.contains_key(credential_id) {
                let mut error = ValidationError::new("invalid_credential_id");
                error.message =
                    Some(format!("Presentation provided for '{credential_id}' which was not requested for.").into());
                errors.add("presentations", error);
            }
        }

        // Check multiple parameter
        for (credential_id, presentations) in &self.presentations {
            if let Some(credential_query) = credential_queries.get(credential_id) {
                let allows_multiple = credential_query.multiple.unwrap_or(false);

                if !allows_multiple && presentations.len() > 1 {
                    let mut error = ValidationError::new("multiple_not_allowed");
                    error.message = Some(
                        format!(
                            "Credential '{}' does not allow multiple presentations, but {} provided",
                            credential_id,
                            presentations.len()
                        )
                        .into(),
                    );
                    errors.add("presentations", error);
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
