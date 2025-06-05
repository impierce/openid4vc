use crate::dcql::dcql_query::{CredentialId, CredentialQuery, DcqlQuery};
use crate::token::vp_token::{DcqlQueryVpToken, PresentationFormat, VpToken};
use anyhow::{anyhow, Result};
use identity_credential::{credential::Jwt, presentation::Presentation};
use oid4vc_core::{builder_fn, RFC7519Claims};
use std::collections::HashMap;
use validator::{Validate, ValidationError, ValidationErrors};
#[derive(Default)]
pub struct VpTokenBuilder {
    rfc7519_claims: RFC7519Claims,
    verifiable_presentation: Option<Presentation<Jwt>>,
    // TODO: Is this required?
    nonce: Option<String>,
}

impl VpTokenBuilder {
    pub fn new() -> Self {
        VpTokenBuilder::default()
    }

    pub fn build(self) -> Result<VpToken> {
        anyhow::ensure!(self.rfc7519_claims.iss.is_some(), "iss claim is required");
        anyhow::ensure!(self.rfc7519_claims.sub.is_some(), "sub claim is required");
        // TODO: According to https://openid.net/specs/openid-connect-core-1_0.html#IDToken, the sub claim MUST NOT
        // exceed 255 ASCII characters in length. However, for `did:jwk` it can be longer so we need to figure out how
        // to deal with this.
        // anyhow::ensure!(
        //     self.rfc7519_claims.sub.as_ref().filter(|s| s.len() <= 255).is_some(),
        //     "sub claim MUST NOT exceed 255 ASCII characters in length"
        // );
        anyhow::ensure!(self.rfc7519_claims.aud.is_some(), "aud claim is required");
        anyhow::ensure!(self.rfc7519_claims.exp.is_some(), "exp claim is required");
        anyhow::ensure!(self.rfc7519_claims.iat.is_some(), "iat claim is required");
        anyhow::ensure!(
            self.rfc7519_claims.iss == self.rfc7519_claims.sub,
            "iss and sub must be equal"
        );

        Ok(VpToken {
            rfc7519_claims: self.rfc7519_claims,
            verifiable_presentation: self
                .verifiable_presentation
                .ok_or_else(|| anyhow!("verifiable_presentation is required"))?,
            nonce: self.nonce,
        })
    }

    builder_fn!(rfc7519_claims, iss, String);
    builder_fn!(rfc7519_claims, sub, String);
    builder_fn!(rfc7519_claims, aud, String);
    builder_fn!(rfc7519_claims, exp, i64);
    builder_fn!(rfc7519_claims, nbf, i64);
    builder_fn!(rfc7519_claims, iat, i64);
    builder_fn!(rfc7519_claims, jti, String);
    builder_fn!(verifiable_presentation, Presentation<Jwt>);
    builder_fn!(nonce, String);
}

#[derive(Default, Validate)]
pub struct DcqlVpTokenBuilder {
    presentations: HashMap<CredentialId, Vec<PresentationFormat>>,
    dcql_query: Option<DcqlQuery>,
}

impl Default for DcqlQueryVpToken {
    fn default() -> Self {
        Self::new()
    }
}

impl DcqlVpTokenBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn builder_dcql_query(dcql_query: DcqlQuery) -> Self {
        Self {
            presentations: HashMap::new(),
            dcql_query: Some(dcql_query),
        }
    }

    pub fn add_presentation(mut self, credential_id: CredentialId, presentation: PresentationFormat) -> Self {
        self.presentations.entry(credential_id).or_default().push(presentation);
        self
    }

    /// for multiple presentations for the same credential_id
    pub fn add_presentations(mut self, credential_id: CredentialId, presentations: Vec<PresentationFormat>) -> Self {
        self.presentations.insert(credential_id, presentations);
        self
    }

    pub fn build(self) -> Result<DcqlQueryVpToken, ValidationErrors> {
        self.validate()?;
        if let Some(ref dcql_query) = self.dcql_query {
            dcql_query.validate()?;
            self.validate_against_dcql(dcql_query)?;
        }

        Ok(DcqlQueryVpToken {
            presentations: self.presentations,
        })
    }

    fn validate_against_dcql(&self, dcql_query: &DcqlQuery) -> Result<(), ValidationErrors> {
        let mut errors = ValidationErrors::new();

        let credential_queries: HashMap<CredentialId, &CredentialQuery> =
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
                error.message = Some(
                    format!(
                        "Presentation provided for '{}' which was not requested for.",
                        credential_id
                    )
                    .into(),
                );
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
