use crate::{
    VpToken,
    dcql::dcql_query::{CredentialQueryId, DcqlQuery, Format},
    dcql_evaluation::evaluate_dcql_query,
    token::vp_token_builder::{VpTokenBuilderError, validate_presentation_submission},
};
use getset::Getters;
use identity_kit::{
    jose::{DefaultVerifier, JwsError, JwsVerifier},
    resolver::KeyResolver,
    sd_jwt_vc::{
        KeyBindingOptions, SdJwt, SdJwtCredentialV2, SdJwtCredentialValidator, SdJwtValidationError,
        SdJwtValidationOptions, SdJwtVc,
    },
    vc::{
        Jwt,
        validation::{
            CredentialValidationOptions, DecodedCredential, JwtPresentationValidator, PresentationValidationError,
            PresentationValidationOptions, StatusCheck, StatusPolicy, TimeOptions, ValidationError,
        },
    },
};
use nutype::nutype;
use oid4vc_core::{JsonObject, types::string_or_object::StringOrObject, utils::predicates::not_empty};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpTokenValidationError {
    #[error("Credential query with id `{0}` not found in DCQL query")]
    CredentialQueryNotFound(CredentialQueryId),
    #[error("Invalid presentation format: expected string")]
    InvalidPresentationFormat,
    #[error("Invalid JWT: {0}")]
    InvalidJwt(#[from] JwsError),
    #[error("Credential validation error: {0}")]
    CredentialValidation(#[from] ValidationError),
    #[error("Presentation validation error: {0}")]
    PresentationValidation(#[from] PresentationValidationError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("SD-JWT parsing error: {0}")]
    SdJwtParsingError(String),
    #[error("SD-JWT validation error: {0}")]
    SdJwtValidation(#[from] SdJwtValidationError),
    #[error("Decoded credentials should not be empty")]
    EmptyDecodedCredentials,
    #[error("Unsupported credential format")]
    UnsupportedFormat,
    #[error("Presentation carries a credential that is not secured as the query's format requires")]
    CredentialFormatMismatch,
    #[error("Decoded credential is not a JSON object")]
    InvalidDecodedCredentialType,
    #[error("DCQL evaluation failed")]
    DcqlEvaluationFailed,
    #[error("Presentation submission validation failed: {0}")]
    PresentationSubmissionValidation(#[from] VpTokenBuilderError),
}

/// Default tolerance for clock differences between the verifier and the holders/issuers whose JWTs it validates.
///
/// Without it, a wallet whose clock runs even slightly ahead produces a presentation whose `iat` lies in the future
/// from the verifier's point of view, which would be rejected. 60 seconds matches the default leeway of the
/// `jsonwebtoken` crate.
pub const DEFAULT_CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(60);

/// The `typ` of a presentation JWT that carries a VCDM 2.0 presentation (`vc+sd-jwt` credentials) but predates the
/// `vp+jwt` media type of VC-JOSE-COSE. `oid4vc_core::jwt::encode` signs a `VerifiablePresentationJwt` under it, and
/// wallets that built presentations with `identity_credential` did too.
const LEGACY_PRESENTATION_TYP: &str = "JWT";

/// A type validating [`VpToken`]s.
///
/// Keys are resolved with a [`KeyResolver`] (for instance a [`Resolver`](identity_kit::resolver::Resolver) with the DID
/// methods the verifier accepts) and signatures verified with a [`JwsVerifier`] ([`DefaultVerifier`] unless another is
/// given). The [`StatusCheck`] receives every `credentialStatus` entry and `status` claim of the presented credentials;
/// `status_list::StatusListCheck` checks the Token Status List. What it does not support is skipped, unless
/// the [`StatusPolicy`] says otherwise ([`with_status_policy`](Self::with_status_policy)).
pub struct VpTokenValidator<R, V = DefaultVerifier> {
    jwt_presentation_validator: JwtPresentationValidator<Arc<R>, Arc<V>>,
    sd_jwt_credential_validator: SdJwtCredentialValidator<Arc<R>, Arc<V>>,
    status_policy: StatusPolicy,
    clock_skew_leeway: Duration,
}

impl<R: KeyResolver + 'static> VpTokenValidator<R> {
    /// Create a new [`VpTokenValidator`] that resolves keys with `resolver`, verifies signatures with
    /// [`DefaultVerifier`] and checks credential status with `status_check`.
    pub fn new(resolver: R, status_check: impl StatusCheck + 'static) -> Self {
        Self::with_verifier(resolver, DefaultVerifier, status_check)
    }
}

impl<R: KeyResolver + 'static, V: JwsVerifier + 'static> VpTokenValidator<R, V> {
    /// Create a new [`VpTokenValidator`] that verifies signatures with `verifier` instead of [`DefaultVerifier`].
    pub fn with_verifier(resolver: R, verifier: V, status_check: impl StatusCheck + 'static) -> Self {
        let resolver = Arc::new(resolver);
        let verifier = Arc::new(verifier);
        let status_check: Arc<dyn StatusCheck> = Arc::new(status_check);
        Self {
            jwt_presentation_validator: JwtPresentationValidator::new(resolver.clone(), verifier.clone())
                .with_status_check(status_check.clone()),
            sd_jwt_credential_validator: SdJwtCredentialValidator::new(resolver, verifier)
                .with_status_check(status_check),
            status_policy: StatusPolicy::SkipUnsupported,
            clock_skew_leeway: DEFAULT_CLOCK_SKEW_LEEWAY,
        }
    }

    /// Override the tolerance for clock differences applied to the issuance and expiration dates of presentations
    /// and credentials. Defaults to [`DEFAULT_CLOCK_SKEW_LEEWAY`].
    pub fn with_clock_skew_leeway(mut self, clock_skew_leeway: Duration) -> Self {
        self.clock_skew_leeway = clock_skew_leeway;
        self
    }

    /// Override what to do about status entries. Defaults to [`StatusPolicy::SkipUnsupported`]: every entry the
    /// [`StatusCheck`] supports must pass, the others are ignored.
    pub fn with_status_policy(mut self, status_policy: StatusPolicy) -> Self {
        self.status_policy = status_policy;
        self
    }

    /// Validate the provided [`VpToken`] against the given [`DcqlQuery`].
    ///
    /// This process involves:
    /// 1. Validating the structural submission of the presentations (e.g. required sets satisfied).
    /// 2. Iterating through presentations in the `vp_token`.
    /// 3. Matching each presentation to a `CredentialQuery` in the `dcql_query`.
    /// 4. Validating the format-specific structure and signatures of each presentation, including the audience
    ///    (`client_id`) and the `nonce` of the presentation or key binding JWT when holder binding is required.
    /// 5. Validating the credentials, their status included, and decoding them into a common format (`JsonObject`).
    /// 6. Evaluating the decoded credentials against the full logic of the `dcql_query` (including sets and claims).
    #[tracing::instrument(level = "debug", err, skip(self, vp_token))]
    pub async fn validate_vp_token(
        &self,
        dcql_query: &DcqlQuery,
        vp_token: &VpToken,
        client_id: &str,
        nonce: &str,
    ) -> Result<DecodedVpToken, VpTokenValidationError> {
        tracing::info!(%client_id, "Validating VP token against DCQL query");

        // Validate that the structural requirements (e.g. required groups) of the DCQL query are met
        validate_presentation_submission(&vp_token.presentations, dcql_query)
            .map_err(VpTokenValidationError::PresentationSubmissionValidation)?;

        let mut builder = DecodedVpTokenBuilder::new();

        for (credential_query_id, presentations) in vp_token.presentations.iter() {
            // Find the corresponding query definition for this presentation ID
            let credential_query = dcql_query
                .credentials
                .iter()
                .find(|credential_query| credential_query.id == *credential_query_id)
                .ok_or_else(|| VpTokenValidationError::CredentialQueryNotFound(credential_query_id.clone()))?;

            let require_holder_binding = credential_query.require_cryptographic_holder_binding.unwrap_or(true);

            tracing::debug!(
                %credential_query_id,
                format = ?credential_query.format,
                require_holder_binding,
                "Validating presentation for credential query"
            );

            // Decode and validate signatures based on format
            let current_query_decoded_credentials = match credential_query.format {
                Format::JwtVcJson => {
                    self.validate_jwt_vc_json_presentations(
                        presentations.as_slice(),
                        client_id,
                        nonce,
                        require_holder_binding,
                    )
                    .await?
                }
                Format::DcSdJwt => {
                    self.validate_dc_sd_jwt_presentations(
                        presentations.as_slice(),
                        client_id,
                        nonce,
                        require_holder_binding,
                    )
                    .await?
                }
                Format::VcSdJwt => {
                    self.validate_vc_sd_jwt_presentations(
                        presentations.as_slice(),
                        client_id,
                        nonce,
                        require_holder_binding,
                    )
                    .await?
                }
                _ => return Err(VpTokenValidationError::UnsupportedFormat),
            };

            builder = builder.insert(credential_query_id.clone(), current_query_decoded_credentials)?;
        }

        let decoded_vp_token = builder.build();

        // Perform semantic validation of the claims requested in the DCQL query
        if !evaluate_dcql_query(dcql_query, &decoded_vp_token) {
            return Err(VpTokenValidationError::DcqlEvaluationFailed);
        }

        tracing::info!("VP token successfully validated against DCQL query");
        Ok(decoded_vp_token)
    }

    /// Validates a list of presentations in `jwt_vc_json` format.
    ///
    /// With holder binding, each presentation is a VCDM 1.1 presentation JWT, validated with the credentials it
    /// carries; every credential subject must be the holder. Without, each presentation is a credential JWT.
    #[tracing::instrument(level = "debug", err, skip(self, presentations))]
    async fn validate_jwt_vc_json_presentations(
        &self,
        presentations: &[StringOrObject],
        client_id: &str,
        nonce: &str,
        require_holder_binding: bool,
    ) -> Result<Vec<JsonObject>, VpTokenValidationError> {
        tracing::debug!(
            count = presentations.len(),
            require_holder_binding,
            "Validating jwt_vc_json presentations"
        );
        let mut decoded_credentials = vec![];
        // TODO: check `multiple`
        for presentation in presentations.iter() {
            let jwt = Jwt::new(as_str(presentation)?)?;

            let credentials = if require_holder_binding {
                self.jwt_presentation_validator
                    .validate(&jwt, &self.presentation_validation_options(client_id, nonce))
                    .await?
                    .credentials
            } else {
                vec![self.validate_credential_jwt(&jwt).await?]
            };

            for credential in credentials {
                decoded_credentials.push(to_json_object(&credential.credential)?);
            }
        }
        Ok(decoded_credentials)
    }

    /// Validates a list of presentations in `dc+sd-jwt` format.
    #[tracing::instrument(level = "debug", err, skip(self, presentations))]
    async fn validate_dc_sd_jwt_presentations(
        &self,
        presentations: &[StringOrObject],
        client_id: &str,
        nonce: &str,
        require_holder_binding: bool,
    ) -> Result<Vec<JsonObject>, VpTokenValidationError> {
        tracing::debug!(
            count = presentations.len(),
            require_holder_binding,
            "Validating dc+sd-jwt presentations"
        );
        let mut decoded_credentials = vec![];
        // TODO: check `multiple`
        for presentation in presentations.iter() {
            let sd_jwt = parse_sd_jwt(as_str(presentation)?)?;

            let sd_jwt_vc = self
                .validate_sd_jwt_vc(&sd_jwt, client_id, nonce, require_holder_binding)
                .await?;

            decoded_credentials.push(sd_jwt_vc.payload().clone());
        }
        Ok(decoded_credentials)
    }

    /// Validates a list of presentations in `vc+sd-jwt` format.
    ///
    /// With holder binding, each presentation is a VCDM 2.0 presentation JWT enveloping `vc+sd-jwt` credentials,
    /// validated with them; every credential subject must be the holder. Without, each presentation is an SD-JWT.
    #[tracing::instrument(level = "debug", err, skip(self, presentations))]
    async fn validate_vc_sd_jwt_presentations(
        &self,
        presentations: &[StringOrObject],
        client_id: &str,
        nonce: &str,
        require_holder_binding: bool,
    ) -> Result<Vec<JsonObject>, VpTokenValidationError> {
        tracing::debug!(
            count = presentations.len(),
            require_holder_binding,
            "Validating vc+sd-jwt presentations"
        );
        let mut decoded_credentials = vec![];
        // TODO: check `multiple`
        for presentation in presentations.iter() {
            let presentation = as_str(presentation)?;

            if require_holder_binding {
                let options = self
                    .presentation_validation_options(client_id, nonce)
                    .with_additional_typ(LEGACY_PRESENTATION_TYP);
                let decoded_presentation = self
                    .jwt_presentation_validator
                    .validate_v2(&Jwt::new(presentation)?, &options)
                    .await?;

                for credential in &decoded_presentation.credentials {
                    let credential = credential
                        .as_sd_jwt()
                        .ok_or(VpTokenValidationError::CredentialFormatMismatch)?;
                    decoded_credentials.push(to_json_object(credential.credential())?);
                }
            } else {
                let credential = self.validate_vcdm2_sd_jwt(&parse_sd_jwt(presentation)?).await?;
                decoded_credentials.push(to_json_object(credential.credential())?);
            }
        }
        Ok(decoded_credentials)
    }

    /// Public helper to validate a credential JWT (VCDM 1.1), since this validator can also be used separately from
    /// the VP token validation process.
    #[tracing::instrument(level = "debug", err, skip(self, credential_jwt))]
    pub async fn validate_credential_jwt(
        &self,
        credential_jwt: &Jwt,
    ) -> Result<DecodedCredential, VpTokenValidationError> {
        // TODO: verify whether issuer is trusted (through `trusted_authorities`).
        Ok(self
            .jwt_presentation_validator
            .credential_validator()
            .validate(credential_jwt, &self.credential_validation_options())
            .await?)
    }

    /// Public helper to validate an SD-JWT VC (signature, key binding, disclosures, status), since this validator can
    /// also be used separately from the VP token validation process. With `require_holder_binding`, the key binding
    /// JWT must be signed by the key of `cnf` and name `client_id` as its audience and `nonce`.
    #[tracing::instrument(level = "debug", err, skip(self, sd_jwt))]
    pub async fn validate_sd_jwt_vc(
        &self,
        sd_jwt: &SdJwt,
        client_id: &str,
        nonce: &str,
        require_holder_binding: bool,
    ) -> Result<SdJwtVc, VpTokenValidationError> {
        let mut options = self.sd_jwt_validation_options();
        if require_holder_binding {
            options = options.with_key_binding(KeyBindingOptions::new(client_id, nonce).with_time(self.time_options()));
        }
        // TODO: verify whether issuer is trusted (through `trusted_authorities`).
        Ok(self
            .sd_jwt_credential_validator
            .validate(sd_jwt, &options)
            .await?
            .credential)
    }

    /// Public helper to validate a VCDM 2.0 credential secured with SD-JWT, since this validator can also be used
    /// separately from the VP token validation process.
    #[tracing::instrument(level = "debug", err, skip(self, vcdm2_sd_jwt))]
    pub async fn validate_vcdm2_sd_jwt(
        &self,
        vcdm2_sd_jwt: &SdJwt,
    ) -> Result<SdJwtCredentialV2, VpTokenValidationError> {
        // TODO: verify whether issuer is trusted (through `trusted_authorities`).
        Ok(self
            .sd_jwt_credential_validator
            .validate_v2(vcdm2_sd_jwt, &self.sd_jwt_validation_options())
            .await?
            .credential)
    }

    /// The validation time (now) with the clock skew leeway.
    fn time_options(&self) -> TimeOptions {
        TimeOptions::default().with_leeway(self.clock_skew_leeway)
    }

    fn credential_validation_options(&self) -> CredentialValidationOptions {
        CredentialValidationOptions::new()
            .with_time(self.time_options())
            .with_status(self.status_policy)
    }

    fn presentation_validation_options(&self, client_id: &str, nonce: &str) -> PresentationValidationOptions {
        PresentationValidationOptions::new()
            .with_time(self.time_options())
            .with_audience(client_id)
            .with_nonce(nonce)
            .with_credentials(self.credential_validation_options())
    }

    fn sd_jwt_validation_options(&self) -> SdJwtValidationOptions {
        SdJwtValidationOptions::new()
            .with_time(self.time_options())
            .with_status(self.status_policy)
    }
}

/// The presentation as the string all supported formats use.
fn as_str(presentation: &StringOrObject) -> Result<&str, VpTokenValidationError> {
    presentation
        .as_str()
        .ok_or(VpTokenValidationError::InvalidPresentationFormat)
}

fn parse_sd_jwt(sd_jwt: &str) -> Result<SdJwt, VpTokenValidationError> {
    SdJwt::parse(sd_jwt).map_err(|e| VpTokenValidationError::SdJwtParsingError(e.to_string()))
}

fn to_json_object(value: &impl Serialize) -> Result<JsonObject, VpTokenValidationError> {
    match serde_json::to_value(value)? {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err(VpTokenValidationError::InvalidDecodedCredentialType),
    }
}

#[derive(Serialize, Clone, Deserialize, Debug, Getters, PartialEq)]
pub struct DecodedVpToken {
    #[serde(flatten)]
    #[getset(get = "pub")]
    decoded_presentations: HashMap<CredentialQueryId, DecodedPresentations>,
}

#[nutype(
    validate(predicate = not_empty),
    derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Deref)
)]
pub struct DecodedPresentations(Vec<JsonObject>);

#[derive(Default)]
pub struct DecodedVpTokenBuilder {
    decoded_presentations: HashMap<CredentialQueryId, DecodedPresentations>,
}

impl DecodedVpTokenBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        mut self,
        credential_query_id: CredentialQueryId,
        decoded_credentials: Vec<JsonObject>,
    ) -> Result<Self, VpTokenValidationError> {
        let decoded_presentations = DecodedPresentations::try_new(decoded_credentials)
            .map_err(|_| VpTokenValidationError::EmptyDecodedCredentials)?;
        self.decoded_presentations
            .insert(credential_query_id, decoded_presentations);
        Ok(self)
    }

    pub fn build(self) -> DecodedVpToken {
        DecodedVpToken {
            decoded_presentations: self.decoded_presentations,
        }
    }
}

// TODO: We need to add credential signing functionality to `VpTokenBuilder` in order to have more thorough tests for the validator. For now, the tests use pre-generated presentations and sign the others themselves.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dcql::dcql_query::{ClaimQuery, CredentialQuery, MetaTypes},
        token::{
            verifiable_presentation_jwt::{VerifiablePresentation, VerifiablePresentationJwt},
            vp_token::Presentations,
        },
    };
    use chrono::{DateTime, Utc};
    use identity_kit::{
        did::{Did, DidUrl},
        jose::{JwsAlgorithm, JwsHeader, KeyType},
        keys::{InMemoryKeyStore, KeySigner, KeySpec, KeyStore as _},
        methods::DidKey,
        resolver::Resolver,
        sd_jwt_vc::{Confirmation, KeyBinding, SdJwtCredentialV2Builder, SdJwtVcBuilder},
        status_list::Status,
        vc::{
            Credential, CredentialV2, EnvelopedVc, JwtClaims, Presentation, PresentationV2, Subject,
            validation::{CredentialStatus, StatusError},
        },
    };
    use oid4vc_core::claim_path_pointer::{ClaimPathElement, ClaimPathPointer};
    use serde_json::json;

    const VALID_JWT_VC_JSON_CREDENTIAL: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkI3o2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCIsInN1YiI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkIiwiYXVkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ejZNa2V1cGVQVktpa0x2NEtYRTk5b0F2UWJnQVI3cVhxM0FHVXRzU2VvcVpnRkJWIiwiZXhwIjo3ODIxMjQ3MjUxLCJpYXQiOjE3NzMyNDcyNTEsInZwIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyVjFjR1ZRVmt0cGEweDJORXRZUlRrNWIwRjJVV0puUVZJM2NWaHhNMEZIVlhSelUyVnZjVnBuUmtKV0kzbzJUV3RsZFhCbFVGWkxhV3RNZGpSTFdFVTVPVzlCZGxGaVowRlNOM0ZZY1ROQlIxVjBjMU5sYjNGYVowWkNWaUo5LmV5SnBjM01pT2lKa2FXUTZhMlY1T25vMlRXdGxkWEJsVUZaTGFXdE1kalJMV0VVNU9XOUJkbEZpWjBGU04zRlljVE5CUjFWMGMxTmxiM0ZhWjBaQ1ZpSXNJbk4xWWlJNkltUnBaRHByWlhrNmVqWk5hMmc1ZVRSTVUwWTRNbTlXY2swM1MzcHhaaloxT0ZWdk1VNTFVRmx5VW01a00yOTNRa3hGUlVGRVRIQmtJaXdpYm1KbUlqb3hOemN6TWpRM01qSTRMQ0pwWVhRaU9qRTNOek15TkRjeU1qZ3NJblpqSWpwN0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbVpwY25OMFgyNWhiV1VpT2lKR1pYSnlhWE1pTENKc1lYTjBYMjVoYldVaU9pSkRjbUZpYldGdUlpd2laRzlpSWpvaU1UazRNaTB3TVMwd01TSXNJbWxrSWpvaVpHbGtPbXRsZVRwNk5rMXJhRGw1TkV4VFJqZ3liMVp5VFRkTGVuRm1OblU0Vlc4eFRuVlFXWEpTYm1RemIzZENURVZGUVVSTWNHUWlmU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSnBjM04xWlhJaU9uc2libUZ0WlNJNklsVnVhVU52Y21VaUxDSnBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyVjFjR1ZRVmt0cGEweDJORXRZUlRrNWIwRjJVV0puUVZJM2NWaHhNMEZIVlhSelUyVnZjVnBuUmtKV0luMHNJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDNZeElsMHNJbWx6YzNWaGJtTmxSR0YwWlNJNklqSXdNall0TURNdE1URlVNVFk2TkRBNk1qaGFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOaTB3TXkweE1WUXhOam8wTURveU9Gb2lMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW5SNWNHVWlPaUp6ZEdGMGRYTnNhWE4wSzJwM2RDSXNJbWxrSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvek1ETXpMMmxsZEdZdGIyRjFkR2d0ZEc5clpXNHRjM1JoZEhWekxXeHBjM1F2TVNJc0luVnlhU0k2SW1oMGRIQTZMeTlzYjJOaGJHaHZjM1E2TXpBek15OXBaWFJtTFc5aGRYUm9MWFJ2YTJWdUxYTjBZWFIxY3kxc2FYTjBMekVpTENKcFpIZ2lPamd3TkRoOWZTd2ljM1JoZEhWeklqcDdJbk4wWVhSMWMxOXNhWE4wSWpwN0luVnlhU0k2SW1oMGRIQTZMeTlzYjJOaGJHaHZjM1E2TXpBek15OXBaWFJtTFc5aGRYUm9MWFJ2YTJWdUxYTjBZWFIxY3kxc2FYTjBMekVpTENKcFpIZ2lPamd3TkRoOWZYMC5fS2lDZUVtZmFfVFFXaVNOTk9hWHZfV3FKNkM5ZkNtLVZTUE53NzVNLVBQS1ZYSGtiNlJiM1lGS25DSVo3M1ZGUVBibWVrX0RwV2F5WWVWTm55NjNBZyJdLCJob2xkZXIiOiJkaWQ6a2V5Ono2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCJ9LCJub25jZSI6ImJlMWExYjIwMDg0ZjY1NjYwMzNkZTdiYzJmOTBiODM3NzIyZmVhYjRhYjZhZjcxY2VjYjg5ZmY0Mjc0NWFiY2QifQ.59V_DEJ2R75iymoUOC67fN2sWvC_W4KaqeDEvamYjbWe-gTHikTzoyH3zxhjj-YbCWhOibQNeSDf8ELn1lCSAg";
    const VALID_VC_SD_JWT_CREDENTIAL: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkI3o2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCJ9.eyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK3NkLWp3dCxleUowZVhBaU9pSjJZeXR6WkMxcWQzUWlMQ0pyYVdRaU9pSmthV1E2YTJWNU9ubzJUV3RsZFhCbFVGWkxhV3RNZGpSTFdFVTVPVzlCZGxGaVowRlNOM0ZZY1ROQlIxVjBjMU5sYjNGYVowWkNWaU42TmsxclpYVndaVkJXUzJsclRIWTBTMWhGT1RsdlFYWlJZbWRCVWpkeFdIRXpRVWRWZEhOVFpXOXhXbWRHUWxZaUxDSmhiR2NpT2lKRlpFUlRRU0o5LmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpmYzJRaU9sc2lSa1JaYzNkemFTMTVlREJoUWtOb2VrVmZiVVJxU21GMmJIRnNUVkZMYmtOSk9HWlpabk5JUjFZMVNTSXNJa3RZYURWdWVXWmtNMUJrZEZWSWNXTXRaSFpvTFhSSWQybDNhMUF5Ym1SaFUzUTNla1ZETkVSSFlrMGlMQ0pQVTFWSVlVdzVhMVpLTUZGclVWUkpkRVZ3VG5aTlowRkJXbTB6UWxoR2NqbHJRMmRqTkVKUmVGZE5JaXdpVlZWM2FISTBURVZzYzNkeVh6QktSSEEzYkZCU2NVdHRRWFYzZWpOT1FWZ3phWGxoWWxKeWNqRm9ieUpkZlN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSmRMQ0p1WVcxbElqb2lWa05FVFNBeUxqQWdVMFF0U2xkVUlFTnlaV1JsYm5ScFlXd2lMQ0pwYzNOMVpYSWlPbnNpYm1GdFpTSTZJbFZ1YVVOdmNtVWlMQ0pwWkNJNkltUnBaRHByWlhrNmVqWk5hMlYxY0dWUVZrdHBhMHgyTkV0WVJUazViMEYyVVdKblFWSTNjVmh4TTBGSFZYUnpVMlZ2Y1ZwblJrSldJbjBzSWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OXVjeTlqY21Wa1pXNTBhV0ZzY3k5Mk1pSmRMQ0pwYzNOMVlXNWpaVVJoZEdVaU9pSXlNREkyTFRBekxURXhWREUyT2pRNU9qVTJXaUlzSW5aaGJHbGtSbkp2YlNJNklqSXdNall0TURNdE1URlVNVFk2TkRrNk5UWmFJaXdpWTNKbFpHVnVkR2xoYkZOMFlYUjFjeUk2ZXlKMGVYQmxJam9pYzNSaGRIVnpiR2x6ZEN0cWQzUWlMQ0pwWkNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk16QXpNeTlwWlhSbUxXOWhkWFJvTFhSdmEyVnVMWE4wWVhSMWN5MXNhWE4wTHpBaUxDSjFjbWtpT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pNd016TXZhV1YwWmkxdllYVjBhQzEwYjJ0bGJpMXpkR0YwZFhNdGJHbHpkQzh3SWl3aWFXUjRJam94T0RaOUxDSnpkR0YwZFhNaU9uc2ljM1JoZEhWelgyeHBjM1FpT25zaWRYSnBJam9pYUhSMGNEb3ZMMnh2WTJGc2FHOXpkRG96TURNekwybGxkR1l0YjJGMWRHZ3RkRzlyWlc0dGMzUmhkSFZ6TFd4cGMzUXZNQ0lzSW1sa2VDSTZNVGcyZlgwc0ltbHpjeUk2SW1ScFpEcHJaWGs2ZWpaTmEyVjFjR1ZRVmt0cGEweDJORXRZUlRrNWIwRjJVV0puUVZJM2NWaHhNMEZIVlhSelUyVnZjVnBuUmtKV0lpd2lYM05rWDJGc1p5STZJbk5vWVMweU5UWWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaVpHbGtPbXRsZVRwNk5rMXJhRGw1TkV4VFJqZ3liMVp5VFRkTGVuRm1OblU0Vlc4eFRuVlFXWEpTYm1RemIzZENURVZGUVVSTWNHUWplalpOYTJnNWVUUk1VMFk0TW05V2NrMDNTM3B4WmpaMU9GVnZNVTUxVUZseVVtNWtNMjkzUWt4RlJVRkVUSEJrSW4xOS5yLVFneXVTNGZlUk5ob3haWHctb2NEQ1NWSzR5S29uZUl1SV9nbks5X3JEVUVlR0lFRnZ3Y0pmQ09FYUtXMVF0OG5FZ0ZzSl80UjVJRFZCRmJKck5EZ35XeUpTU1VoeFJuSm5XR1Z5Y2t0bk4xTmhVMDVXZDNsM2FITmtlVFJrUlZaM1lWVlJTV0pTV1ROTklpd2labWx5YzNSZmJtRnRaU0lzSWtabGNuSnBjeUpkfld5SmhPVGx3VTBoQlIzbE5VbVZOYW5ablRFOUJTVXhXWmw5UFpHbFBUMUZGYldwcFQzcFRhREY0SWl3aWJHRnpkRjl1WVcxbElpd2lRM0poWW0xaGJpSmR-V3lKSFNqZFVabEZxZEdKU1VYSnlPR05WVEdKRlZITlBkMGRqWlhOd2NsRTBkM05xUWxOa01tcFlJaXdpWkc5aUlpd2lNVGs0TWkwd01TMHdNU0pkfld5Sk1kMVZvWDNBMWNqbHZUM2RtVVV4NVZFTm1TbXA0YzJWTU5ERnVORkZUT1VGa1gydGFlVjlWSWl3aWFXUWlMQ0prYVdRNmEyVjVPbm8yVFd0b09YazBURk5HT0RKdlZuSk5OMHQ2Y1dZMmRUaFZiekZPZFZCWmNsSnVaRE52ZDBKTVJVVkJSRXh3WkNKZH4iLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifV0sImhvbGRlciI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkIiwiYXVkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ejZNa2V1cGVQVktpa0x2NEtYRTk5b0F2UWJnQVI3cVhxM0FHVXRzU2VvcVpnRkJWIiwiZXhwIjo3ODIxMjQ4MjA2LCJpYXQiOjE3NzMyNDgyMDYsImlzcyI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkIiwibm9uY2UiOiI4ZGY5MWE0YTE5Y2IxYmFiZGE4YmI1OTlhYmU1MmNhZWFlNWFhODgxOWYzOGQ3NjJkMTM0NDZhZGQ3YmQwOWY0In0.t8Q4bmZAD2hFcQxLQfKWM21yOnzr-syra6fGgh9IuDzXEbm_J4ZiJ6YoD8b7eQkB431TDuRGzx57oEAkD8YgCA";

    // `iat` and `exp` of the presentation in `VALID_JWT_VC_JSON_CREDENTIAL`, and `nbf` of the credential inside it.
    const VALID_JWT_VC_JSON_PRESENTATION_IAT: i64 = 1773247251;
    const VALID_JWT_VC_JSON_PRESENTATION_EXP: i64 = 7821247251;
    const VALID_JWT_VC_JSON_CREDENTIAL_NBF: i64 = 1773247228;

    /// A `dc+sd-jwt` credential UniCore issued, presented without a key binding JWT.
    const UNICORE_DC_SD_JWT_CREDENTIAL: &str = "eyJ0eXAiOiJkYytzZC1qd3QiLCJraWQiOiJkaWQ6a2V5Ono2TWtldXBlUFZLaWtMdjRLWEU5OW9BdlFiZ0FSN3FYcTNBR1V0c1Nlb3FaZ0ZCViN6Nk1rZXVwZVBWS2lrTHY0S1hFOTlvQXZRYmdBUjdxWHEzQUdVdHNTZW9xWmdGQlYiLCJhbGciOiJFZERTQSJ9.eyJ2Y3QiOiJodHRwOi8vbG9jYWxob3N0OjMwMzMvdmN0L1UwUXRTbGRVSUZaRC8wIiwiX3NkIjpbIjhWRjlEYkRnaDJrT0kwWW5Cc0dBQUJuTldIZ1puVWlQOENZVjBRMTFmc00iLCJZSUh1ZDNuUHRDV3c1NkY2OWNLYU1NWDNsOGd1UFgwbVNUcDVPSV9QNVo4IiwidWhpSHdOaUtrQUJDN2tBQUxzU0ZMM0JaeXJnb05McnRGTGNXOHg2SWdwMCJdLCJpc3MiOiJkaWQ6a2V5Ono2TWtldXBlUFZLaWtMdjRLWEU5OW9BdlFiZ0FSN3FYcTNBR1V0c1Nlb3FaZ0ZCViIsIm5iZiI6MTc3MzI0NzQxMywiaWF0IjoxNzczMjQ3NDEzLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsidXJpIjoiaHR0cDovL2xvY2FsaG9zdDozMDMzL2lldGYtb2F1dGgtdG9rZW4tc3RhdHVzLWxpc3QvMCIsImlkeCI6Mzk3N319LCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJraWQiOiJkaWQ6a2V5Ono2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCN6Nk1raDl5NExTRjgyb1ZyTTdLenFmNnU4VW8xTnVQWXJSbmQzb3dCTEVFQURMcGQifX0.-yfZPKWJbeRE45GPqzFIT-wB-f1jXstqR9puEpnobWhY3Ddxf7z1HtZMb4GJcvbOrtcako9ptSxc8keIR-XADw~WyJKbjhUbUh4QmZwLXItd3dCX2h6UEFiS214aEt2R3NMZXJfazBlS21OIiwiZmlyc3RfbmFtZSIsIkZlcnJpcyJd~WyJua0ZZSzV5enZvT0l4c245aF9xcjdHNzJqS2M2ZXo4OVRQZmExb3RYIiwibGFzdF9uYW1lIiwiQ3JhYm1hbiJd~WyJGOUZsRHZ6X0EtbzJuYWw1TzJfaDdoRkQ3MFZTMHlQNFhnczdDQ1U0IiwiZG9iIiwiMTk4Mi0wMS0wMSJd~";

    const VERIFIER: &str = "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV";
    const JWT_VC_JSON_NONCE: &str = "be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd";
    const DC_SD_JWT_NONCE: &str = "1c2c6864a3f4e335712bb7890249d3c46e177dd62e3e93bc3a4d08acde7d4ab4";
    const DC_SD_JWT_VCT: &str = "http://localhost:3033/vct/U0QtSldUIFZD/0";
    const VC_SD_JWT_NONCE: &str = "8df91a4a19cb1babda8bb599abe52caeae5aa8819f38d762d13446add7bd09f4";

    /// A status check that finds every credential valid.
    struct Valid;

    #[async_trait::async_trait]
    impl StatusCheck for Valid {
        async fn check(&self, _: CredentialStatus<'_>, _: DateTime<Utc>) -> Result<(), StatusError> {
            Ok(())
        }
    }

    /// A status check that, like `StatusListCheck`, supports only the `status` claim (Token Status List) and finds
    /// every credential revoked through it.
    struct Revoked;

    #[async_trait::async_trait]
    impl StatusCheck for Revoked {
        async fn check(&self, status: CredentialStatus<'_>, _: DateTime<Utc>) -> Result<(), StatusError> {
            match status {
                CredentialStatus::StatusClaim(_) => Err(StatusError::Invalid("revoked".to_owned())),
                other => Err(StatusError::Unsupported(other.mechanism())),
            }
        }
    }

    /// A signer over a new Ed25519 key, and the `did:key` URL of that key.
    async fn did_key_signer() -> (KeySigner<InMemoryKeyStore>, DidUrl) {
        let store = InMemoryKeyStore::new();
        let key = store
            .generate(KeySpec::new(KeyType::Ed25519, JwsAlgorithm::EdDSA))
            .await
            .unwrap();
        let signer = KeySigner::new(store, key, JwsAlgorithm::EdDSA).await.unwrap();
        let did = DidKey::did(signer.public_jwk()).unwrap();
        let kid = did.join(&format!("#{}", did.method_specific_id())).unwrap();
        (signer, kid)
    }

    /// A `dc+sd-jwt` presentation for `VERIFIER` with `DC_SD_JWT_NONCE`: an SD-JWT VC issued with a new `did:key`
    /// whose `first_name` is disclosed, bound to the `did:key` of a new holder key that signs the key binding JWT.
    async fn dc_sd_jwt_presentation() -> String {
        let (issuer, issuer_kid) = did_key_signer().await;
        let (holder, holder_kid) = did_key_signer().await;
        let now = Utc::now();
        let status: Status = serde_json::from_value(serde_json::json!({
            "status_list": { "uri": "http://localhost:3033/ietf-oauth-token-status-list/0", "idx": 3977 }
        }))
        .unwrap();

        SdJwtVcBuilder::new(DC_SD_JWT_VCT)
            .with_issuer(issuer_kid.did().to_string())
            .with_kid(issuer_kid.to_string())
            .with_issued_at(now)
            .with_not_before(now)
            .with_status(status)
            .with_confirmation(Confirmation::kid(holder_kid.to_string()))
            .with_claim("first_name", "Ferris")
            .with_claim("last_name", "Crabman")
            .conceal(["first_name"])
            .conceal(["last_name"])
            .sign(&issuer)
            .await
            .unwrap()
            .sign_key_binding(&KeyBinding::new(VERIFIER, DC_SD_JWT_NONCE, now), &holder)
            .await
            .unwrap()
            .to_string()
    }

    /// A `jwt_vc_json` presentation for `VERIFIER` with `JWT_VC_JSON_NONCE`, signed by a new holder `did:key`, of a
    /// credential issued with a new `did:key` whose `kid` is relative to its `iss`. The credential is about `subject`,
    /// or about the holder when `None`.
    async fn jwt_vc_json_presentation(subject: Option<Did>) -> String {
        let (issuer, issuer_kid) = did_key_signer().await;
        let (holder, holder_kid) = did_key_signer().await;
        let now = Utc::now();
        let subject = subject.unwrap_or_else(|| holder_kid.did().clone());

        let credential = Credential::new(
            issuer_kid.did(),
            now,
            Subject::new(&subject).with_property("first_name", "Ferris"),
        )
        // Two types, so that `type` is an array, which is what DCQL evaluation reads.
        .with_type("PersonalInformation");
        let credential_header = JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_typ("JWT")
            .with_kid(format!("#{}", issuer_kid.did().method_specific_id()));
        let credential = Jwt::sign(&credential_header, &credential.to_jwt_claims().unwrap(), &issuer)
            .await
            .unwrap();

        let presentation = Presentation::new()
            .with_holder(holder_kid.did())
            .with_credential(credential);
        sign_presentation(presentation.into(), JWT_VC_JSON_NONCE, &holder, &holder_kid).await
    }

    /// A `vc+sd-jwt` presentation for `VERIFIER` with `VC_SD_JWT_NONCE`, signed by a new holder `did:key`, of a VCDM
    /// 2.0 credential about the holder, issued with a new `did:key` and secured with SD-JWT, its `first_name`
    /// disclosed.
    async fn vc_sd_jwt_presentation() -> String {
        let (issuer, issuer_kid) = did_key_signer().await;
        let (holder, holder_kid) = did_key_signer().await;

        let credential = CredentialV2::new(
            issuer_kid.did(),
            Subject::new(holder_kid.did()).with_property("first_name", "Ferris"),
        )
        // Two types, so that `type` is an array, which is what DCQL evaluation reads.
        .with_type("PersonalInformation");
        let credential = SdJwtCredentialV2Builder::new(credential)
            .with_kid(issuer_kid.as_str())
            .with_issued_at(Utc::now())
            .conceal(["credentialSubject", "first_name"])
            .sign(&issuer)
            .await
            .unwrap();
        let presentation = PresentationV2::new()
            .with_holder(holder_kid.did())
            .with_credential(EnvelopedVc::from_sd_jwt(credential.sd_jwt()));
        sign_presentation(presentation.into(), VC_SD_JWT_NONCE, &holder, &holder_kid).await
    }

    /// `presentation`, built into a [`VerifiablePresentationJwt`] for `VERIFIER` with `nonce` and signed by `holder`,
    /// under `typ: JWT` as `oid4vc_core::jwt::encode` signs it.
    async fn sign_presentation(
        presentation: VerifiablePresentation,
        nonce: &str,
        holder: &KeySigner<InMemoryKeyStore>,
        holder_kid: &DidUrl,
    ) -> String {
        let now = Utc::now().timestamp();
        let presentation = VerifiablePresentationJwt::builder()
            .iss(holder_kid.did().to_string())
            .sub(holder_kid.did().to_string())
            .aud(VERIFIER.to_string())
            .iat(now)
            .exp(now + 600)
            .nonce(nonce.to_string())
            .verifiable_presentation(presentation)
            .build()
            .unwrap();
        let claims: JwtClaims = serde_json::from_value(serde_json::to_value(&presentation).unwrap()).unwrap();
        let header = JwsHeader::new(JwsAlgorithm::EdDSA)
            .with_typ("JWT")
            .with_kid(holder_kid.as_str());
        Jwt::sign(&header, &claims, holder).await.unwrap().as_str().to_owned()
    }

    fn resolver() -> Resolver {
        Resolver::builder().with(DidKey::default()).build()
    }

    fn validator() -> VpTokenValidator<Resolver> {
        VpTokenValidator::new(resolver(), Valid)
    }

    /// The future of `validate_vp_token` is `Send`, so it can run in a spawned task such as a web handler.
    #[test]
    fn validate_vp_token_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}

        let validator = validator();
        let dcql_query = dcql_query(Format::DcSdJwt, &["first_name"]);
        let vp_token: VpToken =
            serde_json::from_value(json!({ "CredentialQuery": [UNICORE_DC_SD_JWT_CREDENTIAL] })).unwrap();
        assert_send(&validator.validate_vp_token(&dcql_query, &vp_token, VERIFIER, DC_SD_JWT_NONCE));
    }

    /// A DCQL query with one credential query `CredentialQuery` of `format`, asking for the claim at `path`.
    fn dcql_query(format: Format, path: &[&str]) -> DcqlQuery {
        let meta = match format {
            Format::DcSdJwt => MetaTypes::SdJwtMeta {
                vct_values: vec![DC_SD_JWT_VCT.to_string()],
            },
            _ => MetaTypes::W3CFormatMeta {
                type_values: vec![vec!["VerifiableCredential".to_string()]],
            },
        };
        DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format,
                multiple: None,
                meta,
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(
                        path.iter()
                            .map(|element| ClaimPathElement::String(element.to_string()))
                            .collect(),
                    )
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        }
    }

    /// The one credential `decoded` holds for `CredentialQuery`.
    fn decoded_credential(decoded: &DecodedVpToken) -> serde_json::Value {
        serde_json::Value::Object(
            decoded.decoded_presentations()[&CredentialQueryId::try_new("CredentialQuery").unwrap()][0].clone(),
        )
    }

    fn vp_token(credential_query_id: &str, presentation: &str) -> VpToken {
        VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new(credential_query_id).unwrap(),
                Presentations::try_new(vec![presentation.into()]).unwrap(),
            )
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_validate_vp_token_with_jwt_vc_json() {
        let decoded = validator()
            .validate_vp_token(
                &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                VERIFIER,
                JWT_VC_JSON_NONCE,
            )
            .await
            .unwrap();

        // The credential in full, as verifiers store and return it. `issuer` stays the object the credential
        // carries, and `validFrom` is kept; the validator over `identity_credential` reduced `issuer` to its `id`
        // and dropped `validFrom`.
        assert_eq!(
            decoded_credential(&decoded),
            json!({
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiableCredential"],
                "issuer": {"id": "did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV", "name": "UniCore"},
                "issuanceDate": "2026-03-11T16:40:28Z",
                "validFrom": "2026-03-11T16:40:28Z",
                "credentialSubject": {
                    "id": "did:key:z6Mkh9y4LSF82oVrM7Kzqf6u8Uo1NuPYrRnd3owBLEEADLpd",
                    "first_name": "Ferris",
                    "last_name": "Crabman",
                    "dob": "1982-01-01",
                },
                "credentialStatus": {
                    "id": "http://localhost:3033/ietf-oauth-token-status-list/1",
                    "type": "statuslist+jwt",
                    "uri": "http://localhost:3033/ietf-oauth-token-status-list/1",
                    "idx": 8048,
                },
            })
        );
    }

    #[tokio::test]
    async fn test_validate_vp_token_with_dc_sd_jwt() {
        let decoded = validator()
            .validate_vp_token(
                &dcql_query(Format::DcSdJwt, &["first_name"]),
                &vp_token("CredentialQuery", &dc_sd_jwt_presentation().await),
                VERIFIER,
                DC_SD_JWT_NONCE,
            )
            .await
            .unwrap();

        let credential = &decoded.decoded_presentations()[&CredentialQueryId::try_new("CredentialQuery").unwrap()][0];
        assert_eq!(credential["first_name"], "Ferris");
    }

    /// A `dc+sd-jwt` credential decodes to its claims with the disclosures applied, compared in full: the same
    /// object the validator over `sd-jwt-payload` returned.
    #[tokio::test]
    async fn dc_sd_jwt_decodes_to_the_disclosed_claims() {
        let mut dcql_query = dcql_query(Format::DcSdJwt, &["first_name"]);
        dcql_query.credentials[0].require_cryptographic_holder_binding = Some(false);
        let decoded = validator()
            .validate_vp_token(
                &dcql_query,
                &vp_token("CredentialQuery", UNICORE_DC_SD_JWT_CREDENTIAL),
                VERIFIER,
                DC_SD_JWT_NONCE,
            )
            .await
            .unwrap();

        assert_eq!(
            decoded_credential(&decoded),
            json!({
                "vct": DC_SD_JWT_VCT,
                "iss": "did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                "nbf": 1773247413,
                "iat": 1773247413,
                "status": {"status_list": {"uri": "http://localhost:3033/ietf-oauth-token-status-list/0", "idx": 3977}},
                "cnf": {
                    "kid": "did:key:z6Mkh9y4LSF82oVrM7Kzqf6u8Uo1NuPYrRnd3owBLEEADLpd#z6Mkh9y4LSF82oVrM7Kzqf6u8Uo1NuPYrRnd3owBLEEADLpd"
                },
                "first_name": "Ferris",
                "last_name": "Crabman",
                "dob": "1982-01-01",
            })
        );
    }

    #[tokio::test]
    async fn test_validate_vp_token_with_vc_sd_jwt() {
        let decoded = validator()
            .validate_vp_token(
                &dcql_query(Format::VcSdJwt, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", VALID_VC_SD_JWT_CREDENTIAL),
                VERIFIER,
                VC_SD_JWT_NONCE,
            )
            .await
            .unwrap();

        // The VCDM 2.0 credential in full, with the disclosures applied. The JWT claims beside it (`iss`, `cnf`,
        // `status`) are not part of it; the validator over `identity_credential` merged them in.
        assert_eq!(
            decoded_credential(&decoded),
            json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential"],
                "name": "VCDM 2.0 SD-JWT Credential",
                "issuer": {"id": "did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV", "name": "UniCore"},
                "issuanceDate": "2026-03-11T16:49:56Z",
                "validFrom": "2026-03-11T16:49:56Z",
                "credentialSubject": {
                    "id": "did:key:z6Mkh9y4LSF82oVrM7Kzqf6u8Uo1NuPYrRnd3owBLEEADLpd",
                    "first_name": "Ferris",
                    "last_name": "Crabman",
                    "dob": "1982-01-01",
                },
                "credentialStatus": {
                    "id": "http://localhost:3033/ietf-oauth-token-status-list/0",
                    "type": "statuslist+jwt",
                    "uri": "http://localhost:3033/ietf-oauth-token-status-list/0",
                    "idx": 186,
                },
            })
        );
    }

    /// A `jwt_vc_json` presentation built with `VerifiablePresentationJwt` validates, with a credential whose `kid`
    /// is relative to its `iss`.
    #[tokio::test]
    async fn kid_relative_to_did_issuer_is_resolved() {
        validator()
            .validate_vp_token(
                &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", &jwt_vc_json_presentation(None).await),
                VERIFIER,
                JWT_VC_JSON_NONCE,
            )
            .await
            .unwrap();
    }

    /// A `vc+sd-jwt` presentation built with `VerifiablePresentationJwt` validates.
    #[tokio::test]
    async fn vc_sd_jwt_presentation_built_with_verifiable_presentation_jwt_validates() {
        let decoded = validator()
            .validate_vp_token(
                &dcql_query(Format::VcSdJwt, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", &vc_sd_jwt_presentation().await),
                VERIFIER,
                VC_SD_JWT_NONCE,
            )
            .await
            .unwrap();

        let credential = &decoded.decoded_presentations()[&CredentialQueryId::try_new("CredentialQuery").unwrap()][0];
        assert_eq!(credential["credentialSubject"]["first_name"], "Ferris");
    }

    #[tokio::test]
    async fn credential_about_another_subject_results_in_subject_holder_mismatch() {
        let other = Did::parse("did:example:c276e12ec21ebfeb1f712ebc6f1").unwrap();
        let error = validator()
            .validate_vp_token(
                &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", &jwt_vc_json_presentation(Some(other)).await),
                VERIFIER,
                JWT_VC_JSON_NONCE,
            )
            .await
            .unwrap_err();

        let VpTokenValidationError::PresentationValidation(error) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(matches!(
            error.credentials.get(&0),
            Some(ValidationError::SubjectHolderMismatch { .. })
        ));
    }

    /// The credential of `VALID_JWT_VC_JSON_CREDENTIAL` has a `credentialStatus` entry, which `Revoked` does not
    /// support, and a `status` claim, through which it is revoked.
    #[tokio::test]
    async fn invalid_credential_status_results_in_status_error() {
        let error = VpTokenValidator::new(resolver(), Revoked)
            .validate_vp_token(
                &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                VERIFIER,
                JWT_VC_JSON_NONCE,
            )
            .await
            .unwrap_err();

        let VpTokenValidationError::PresentationValidation(error) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(matches!(
            error.credentials.get(&0),
            Some(ValidationError::Status(StatusError::Invalid(_)))
        ));
    }

    #[tokio::test]
    async fn invalid_sd_jwt_credential_status_results_in_status_error() {
        let error = VpTokenValidator::new(resolver(), Revoked)
            .validate_vp_token(
                &dcql_query(Format::DcSdJwt, &["first_name"]),
                &vp_token("CredentialQuery", &dc_sd_jwt_presentation().await),
                VERIFIER,
                DC_SD_JWT_NONCE,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            VpTokenValidationError::SdJwtValidation(SdJwtValidationError::Validation(ValidationError::Status(
                StatusError::Invalid(_)
            )))
        ));
    }

    #[tokio::test]
    async fn status_is_not_checked_under_skip_all() {
        assert!(
            VpTokenValidator::new(resolver(), Revoked)
                .with_status_policy(StatusPolicy::SkipAll)
                .validate_vp_token(
                    &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                    &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                    VERIFIER,
                    JWT_VC_JSON_NONCE,
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn missing_credential_claim_results_in_dcql_evaluation_fail() {
        assert!(matches!(
            validator()
                .validate_vp_token(
                    // This claim does not exist in the credential, so the DCQL evaluation should fail
                    &dcql_query(Format::JwtVcJson, &["credentialSubject", "different_claim"]),
                    &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                    VERIFIER,
                    JWT_VC_JSON_NONCE,
                )
                .await
                .unwrap_err(),
            VpTokenValidationError::DcqlEvaluationFailed
        ));
    }

    #[tokio::test]
    async fn nonce_mismatch_results_in_nonce_mismatch_error() {
        let error = validator()
            .validate_vp_token(
                &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                VERIFIER,
                // This nonce does not match the one in the VP token.
                "different nonce that does not match the one in the VP token",
            )
            .await
            .unwrap_err();

        let VpTokenValidationError::PresentationValidation(error) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(matches!(
            error.presentation.as_deref(),
            Some(ValidationError::NonceMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn nonce_mismatch_in_key_binding_jwt_results_in_nonce_mismatch_error() {
        assert!(matches!(
            validator()
                .validate_vp_token(
                    &dcql_query(Format::DcSdJwt, &["first_name"]),
                    &vp_token("CredentialQuery", &dc_sd_jwt_presentation().await),
                    VERIFIER,
                    "different nonce that does not match the one in the key binding JWT",
                )
                .await
                .unwrap_err(),
            VpTokenValidationError::SdJwtValidation(SdJwtValidationError::Validation(
                ValidationError::NonceMismatch { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn missing_key_binding_jwt_results_in_key_binding_required_error() {
        let without_key_binding = SdJwt::parse(&dc_sd_jwt_presentation().await)
            .unwrap()
            .without_key_binding()
            .to_string();

        assert!(matches!(
            validator()
                .validate_vp_token(
                    &dcql_query(Format::DcSdJwt, &["first_name"]),
                    &vp_token("CredentialQuery", &without_key_binding),
                    VERIFIER,
                    DC_SD_JWT_NONCE,
                )
                .await
                .unwrap_err(),
            VpTokenValidationError::SdJwtValidation(SdJwtValidationError::KeyBindingRequired)
        ));
    }

    #[tokio::test]
    async fn wrong_credential_format_results_in_presentation_validation_error() {
        assert!(matches!(
            validator()
                .validate_vp_token(
                    // This DCQL query is looking for a VC SD-JWT credential, but the VP token will contain a JWT VC
                    // JSON credential.
                    &dcql_query(Format::VcSdJwt, &["credentialSubject", "first_name"]),
                    &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                    VERIFIER,
                    JWT_VC_JSON_NONCE,
                )
                .await
                .unwrap_err(),
            // The VCDM 1.1 presentation carries its credentials in a `vp` claim, which a VCDM 2.0 presentation never
            // has.
            VpTokenValidationError::PresentationValidation(_)
        ));
    }

    #[tokio::test]
    async fn client_id_mismatch_results_in_audience_mismatch_error() {
        let error = validator()
            .validate_vp_token(
                &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                &vp_token("CredentialQuery", VALID_JWT_VC_JSON_CREDENTIAL),
                // The client ID (audience) does not match the one in the VP token.
                "decentralized_identifier:did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF",
                JWT_VC_JSON_NONCE,
            )
            .await
            .unwrap_err();

        let VpTokenValidationError::PresentationValidation(error) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(matches!(
            error.presentation.as_deref(),
            Some(ValidationError::AudienceMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn credential_query_id_mismatch_results_in_presentation_submission_validation_error() {
        assert!(matches!(
            validator()
                .validate_vp_token(
                    &dcql_query(Format::JwtVcJson, &["credentialSubject", "first_name"]),
                    // The VP token contains a presentation for a Credential Query with a different ID.
                    &vp_token("DifferentCredentialQueryID", VALID_JWT_VC_JSON_CREDENTIAL),
                    VERIFIER,
                    JWT_VC_JSON_NONCE,
                )
                .await
                .unwrap_err(),
            VpTokenValidationError::PresentationSubmissionValidation(VpTokenBuilderError::MissingRequiredCredential(_))
        ));
    }

    fn at(now: i64, leeway: Duration) -> TimeOptions {
        TimeOptions::at(DateTime::from_timestamp(now, 0).unwrap()).with_leeway(leeway)
    }

    /// Validates the presentation JWT of `VALID_JWT_VC_JSON_CREDENTIAL` as if the verifier's clock read `now`.
    async fn validate_fixture_presentation_at(
        now: i64,
        leeway: Duration,
    ) -> Result<identity_kit::vc::validation::DecodedPresentation, PresentationValidationError> {
        let time = at(now, leeway);
        JwtPresentationValidator::new(resolver(), DefaultVerifier)
            .validate(
                &Jwt::new(VALID_JWT_VC_JSON_CREDENTIAL).unwrap(),
                &PresentationValidationOptions::new().with_time(time).with_credentials(
                    CredentialValidationOptions::new()
                        .with_time(time)
                        .with_status(StatusPolicy::SkipAll),
                ),
            )
            .await
    }

    fn is_issued_in_future_error(error: &PresentationValidationError) -> bool {
        matches!(
            error.presentation.as_deref(),
            Some(ValidationError::IssuedInFuture { .. })
        )
    }

    #[tokio::test]
    async fn presentation_issued_slightly_in_the_future_is_accepted_within_leeway() {
        // A wallet whose clock runs one second ahead of the verifier's.
        let now = VALID_JWT_VC_JSON_PRESENTATION_IAT - 1;

        assert!(
            validate_fixture_presentation_at(now, DEFAULT_CLOCK_SKEW_LEEWAY)
                .await
                .is_ok()
        );

        let error = validate_fixture_presentation_at(now, Duration::ZERO).await.unwrap_err();
        assert!(is_issued_in_future_error(&error));
    }

    #[tokio::test]
    async fn presentation_issued_beyond_leeway_is_rejected() {
        let now = VALID_JWT_VC_JSON_PRESENTATION_IAT - 61;

        let error = validate_fixture_presentation_at(now, DEFAULT_CLOCK_SKEW_LEEWAY)
            .await
            .unwrap_err();
        assert!(is_issued_in_future_error(&error));
    }

    fn is_expired_error(error: &PresentationValidationError) -> bool {
        matches!(error.presentation.as_deref(), Some(ValidationError::Expired { .. }))
    }

    #[tokio::test]
    async fn presentation_expired_slightly_is_accepted_within_leeway() {
        // A wallet whose clock runs 30 seconds behind the verifier's.
        let now = VALID_JWT_VC_JSON_PRESENTATION_EXP + 30;

        assert!(
            validate_fixture_presentation_at(now, DEFAULT_CLOCK_SKEW_LEEWAY)
                .await
                .is_ok()
        );

        let error = validate_fixture_presentation_at(now, Duration::ZERO).await.unwrap_err();
        assert!(is_expired_error(&error));
    }

    #[tokio::test]
    async fn presentation_expired_beyond_leeway_is_rejected() {
        let now = VALID_JWT_VC_JSON_PRESENTATION_EXP + 61;

        let error = validate_fixture_presentation_at(now, DEFAULT_CLOCK_SKEW_LEEWAY)
            .await
            .unwrap_err();
        assert!(is_expired_error(&error));
    }

    #[tokio::test]
    async fn credential_valid_slightly_in_the_future_is_accepted_within_leeway() {
        let presentation = validate_fixture_presentation_at(VALID_JWT_VC_JSON_PRESENTATION_IAT, Duration::ZERO)
            .await
            .unwrap();
        let credential_jwt = &presentation.presentation.verifiable_credential[0];

        let validator = JwtPresentationValidator::new(resolver(), DefaultVerifier);
        let validate = |now: i64, leeway| {
            let options = CredentialValidationOptions::new()
                .with_time(at(now, leeway))
                .with_status(StatusPolicy::SkipAll);
            let validator = &validator;
            async move {
                validator
                    .credential_validator()
                    .validate(credential_jwt, &options)
                    .await
            }
        };
        let is_not_yet_valid_error = |error: ValidationError| matches!(error, ValidationError::NotYetValid { .. });

        // An issuer whose clock runs 30 seconds ahead of the verifier's.
        let now = VALID_JWT_VC_JSON_CREDENTIAL_NBF - 30;
        assert!(validate(now, DEFAULT_CLOCK_SKEW_LEEWAY).await.is_ok());

        assert!(is_not_yet_valid_error(validate(now, Duration::ZERO).await.unwrap_err()));

        // An issuer whose clock runs 61 seconds ahead of the verifier's.
        assert!(is_not_yet_valid_error(
            validate(VALID_JWT_VC_JSON_CREDENTIAL_NBF - 61, DEFAULT_CLOCK_SKEW_LEEWAY)
                .await
                .unwrap_err()
        ));
    }
}
