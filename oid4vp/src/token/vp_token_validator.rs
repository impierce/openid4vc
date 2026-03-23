use crate::{
    dcql::dcql_query::{CredentialQuery, CredentialQueryId, DcqlQuery, Format},
    dcql_evaluation::evaluate_dcql_query,
    token::vp_token_builder::{validate_presentation_submission, VpTokenBuilderError},
    VpToken,
};
use getset::Getters;
use identity_credential::{
    credential::{CredentialV2, EnvelopedVc, Jwt},
    sd_jwt_payload::{SdJwt, Sha256Hasher},
    sd_jwt_vc::SdJwtVc,
    validator::{
        DecodedJwtCredential, DecodedJwtPresentation, FailFast, JwtCredentialValidationOptions, JwtCredentialValidator,
        JwtPresentationValidator, SdJwtCredentialValidator, StatusCheck,
    },
};
use identity_did::DIDUrl;
use identity_verification::jws::{Decoder, JwsVerifier};
use nutype::nutype;
use oauth_tsl::{
    relying_party::{decompress_gzip, decrypt_status_list_token, StatusListTokenResponseType},
    status_list::{StatusList, StatusType},
};
use oid4vc_core::utils::predicates::not_empty;
use oid4vc_core::{
    types::string_or_object::StringOrObject, verification_material_resolver::VerificationMaterialResolver, JsonObject,
};
use reqwest::{header, redirect::Policy, Client};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use thiserror::Error;

use identity_core::convert::{FromJson as _, ToJson as _};
use jsonwebtoken::{decode_header, jwk::Jwk as JsonWebTokenJwk, DecodingKey};

#[derive(Debug, Error)]
pub enum VpTokenValidationError {
    #[error("Credential query with id `{0}` not found in DCQL query")]
    CredentialQueryNotFound(CredentialQueryId),
    #[error("Invalid presentation format: expected string")]
    InvalidPresentationFormat,
    #[error("JWS decoding error: {0}")]
    JwsDecodingError(#[from] identity_jose::error::Error),
    #[error("Invalid KID: {0}")]
    InvalidKid(String),
    #[error("Verification material resolution error: {0}")]
    VerificationMaterialResolutionError(String),
    #[error("JWT validation error: {0}")]
    JwtValidation(#[from] identity_credential::validator::JwtValidationError),
    #[error("Credential validation error: {0}")]
    CredentialValidation(#[from] identity_credential::validator::CompoundCredentialValidationError),
    #[error("Presentation validation error: {0}")]
    PresentationValidation(#[from] identity_credential::validator::CompoundJwtPresentationValidationError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("SD-JWT parsing error: {0}")]
    SdJwtParsingError(String),
    #[error("SD-JWT validation error: {0}")]
    SdJwtValidation(String),
    #[error("Invalid audience: expected {expected:?}, found {found:?}")]
    InvalidAudience {
        expected: Option<String>,
        found: Option<String>,
    },
    #[error("Invalid nonce: expected {expected:?}, found {found:?}")]
    InvalidNonce {
        expected: Option<String>,
        found: Option<String>,
    },
    #[error("Missing holder binding")]
    MissingHolderBinding,
    #[error("Missing custom claims in presentation")]
    MissingCustomClaims,
    #[error("Decoded credentials should not be empty")]
    EmptyDecodedCredentials,
    #[error("Unsupported credential format")]
    UnsupportedFormat,
    #[error("Decoded credential is not a JSON object")]
    InvalidDecodedCredentialType,
    #[error("Missing KID in header")]
    MissingKid,
    #[error("DCQL evaluation failed")]
    DcqlEvaluationFailed,
    #[error("Presentation submission validation failed: {0}")]
    PresentationSubmissionValidation(#[from] VpTokenBuilderError),
    #[error("Failed to get credential status: {0}")]
    FailedToGetCredentialStatus(String),
    #[error("Credential status is invalid")]
    CredentialStatusInvalid,
}

/// A type validating [`VpToken`]s.
pub struct VpTokenValidator<'a, V: JwsVerifier, VMR: VerificationMaterialResolver> {
    jwt_presentation_validator: JwtPresentationValidator<V>,
    jwt_credential_validator: JwtCredentialValidator<V>,
    sd_jwt_credential_validator: SdJwtCredentialValidator<V>,
    signature_verifier: &'a V,
    verification_material_resolver: &'a VMR,
}

impl<'a, SV: JwsVerifier + Clone, VMR: VerificationMaterialResolver> VpTokenValidator<'a, SV, VMR> {
    /// Create a new [`VpTokenValidator`] that delegates cryptographic signature verification to
    /// `signature_verifier` and resolves DIDs using `verification_material_resolver`
    pub fn new(signature_verifier: &'a SV, verification_material_resolver: &'a VMR) -> Self {
        Self {
            jwt_presentation_validator: JwtPresentationValidator::with_signature_verifier(signature_verifier.clone()),
            jwt_credential_validator: JwtCredentialValidator::with_signature_verifier(signature_verifier.clone()),
            sd_jwt_credential_validator: SdJwtCredentialValidator::new(signature_verifier.clone(), Sha256Hasher),
            signature_verifier,
            verification_material_resolver,
        }
    }

    /// Validate the provided [`VpToken`] against the given [`DcqlQuery`].
    ///
    /// This process involves:
    /// 1. Validating the structural submission of the presentations (e.g. required sets satisfied).
    /// 2. Iterating through presentations in the `vp_token`.
    /// 3. Matching each presentation to a `CredentialQuery` in the `dcql_query`.
    /// 4. Validating the format-specific structure and signatures of each presentation.
    /// 5. Decoding the credentials into a common format (`JsonObject`).
    /// 6. Evaluating the decoded credentials against the full logic of the `dcql_query` (including sets and claims).
    pub async fn validate_vp_token(
        &self,
        dcql_query: &DcqlQuery,
        vp_token: &VpToken,
        client_id: &str,
        nonce: Option<&str>,
    ) -> Result<DecodedVpToken, VpTokenValidationError> {
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
                    self.validate_vc_sd_jwt_presentations(presentations.as_slice(), credential_query, client_id, nonce)
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

        Ok(decoded_vp_token)
    }

    /// Validates a list of presentations in `jwt_vc_json` format.
    /// For each presentation, it verifies the signature and structural validity,
    /// then extracts the internal credential.
    async fn validate_jwt_vc_json_presentations(
        &self,
        presentations: &[StringOrObject],
        client_id: &str,
        nonce: Option<&str>,
        require_holder_binding: bool,
    ) -> Result<Vec<JsonObject>, VpTokenValidationError> {
        let mut decoded_credentials = vec![];
        // TODO: check `multiple`
        for presentation in presentations.iter() {
            let presentation_str = presentation
                .as_str()
                .ok_or(VpTokenValidationError::InvalidPresentationFormat)?;
            let jwt = Jwt::new(presentation_str.to_string());

            // If holder binding is required, we validate the presentation JWT itself (which proves possession).
            // Otherwise, we treat the input directly as a credential JWT (if that's the model, though typically
            // VP-Token implies a presentation wrapper).
            let credential_jwts = if require_holder_binding {
                let decoded_jwt_presentation: DecodedJwtPresentation<Jwt> =
                    self.validate_presentation_jwt(&jwt, client_id, nonce).await?;

                decoded_jwt_presentation.presentation.verifiable_credential
            } else {
                vec![jwt]
            };

            for credential_jwt in credential_jwts {
                let decoded_credential = self.validate_credential_jwt(&credential_jwt).await?;

                let obj = serde_json::to_value(decoded_credential.credential)?
                    .as_object()
                    .cloned()
                    .ok_or(VpTokenValidationError::InvalidDecodedCredentialType)?;
                decoded_credentials.push(obj);
            }
        }
        Ok(decoded_credentials)
    }

    /// Validates a list of presentations in `dc+sd-jwt` format.
    async fn validate_dc_sd_jwt_presentations(
        &self,
        presentations: &[StringOrObject],
        client_id: &str,
        nonce: Option<&str>,
        require_holder_binding: bool,
    ) -> Result<Vec<JsonObject>, VpTokenValidationError> {
        let mut decoded_credentials = vec![];
        // TODO: check `multiple`
        for presentation in presentations.iter() {
            let presentation_str = presentation
                .as_str()
                .ok_or(VpTokenValidationError::InvalidPresentationFormat)?;
            let sd_jwt_vc = SdJwtVc::parse(presentation_str)
                .map_err(|e| VpTokenValidationError::SdJwtParsingError(e.to_string()))?;

            let decoded_sd_jwt_vc = self
                .validate_sd_jwt_vc(&sd_jwt_vc, client_id, nonce, require_holder_binding)
                .await?;

            let obj = serde_json::to_value(decoded_sd_jwt_vc)?
                .as_object()
                .cloned()
                .ok_or(VpTokenValidationError::InvalidDecodedCredentialType)?;
            decoded_credentials.push(obj);
        }
        Ok(decoded_credentials)
    }

    /// Validates a list of presentations in `vc+sd-jwt` format.
    async fn validate_vc_sd_jwt_presentations(
        &self,
        presentations: &[StringOrObject],
        credential_query: &CredentialQuery,
        client_id: &str,
        nonce: Option<&str>,
    ) -> Result<Vec<JsonObject>, VpTokenValidationError> {
        let mut decoded_credentials = vec![];
        // TODO: check `multiple`
        for presentation in presentations.iter() {
            let presentation_str = presentation
                .as_str()
                .ok_or(VpTokenValidationError::InvalidPresentationFormat)?;
            let jwt = Jwt::new(presentation_str.to_string());

            // Similar logic to standard JWTs: verify holder binding if required by extracting SD-JWTs
            // from the validated presentation wrapper.
            let sd_jwts: Vec<SdJwt> = if credential_query.require_cryptographic_holder_binding.unwrap_or(true) {
                let decoded_jwt_presentation: DecodedJwtPresentation<EnvelopedVc> =
                    self.validate_presentation_jwt(&jwt, client_id, nonce).await?;

                decoded_jwt_presentation
                    .presentation
                    .verifiable_credential
                    .iter()
                    .map(|cred| {
                        SdJwt::parse(cred.id.encoded_data())
                            .map_err(|e| VpTokenValidationError::SdJwtParsingError(e.to_string()))
                    })
                    .collect::<Result<_, _>>()?
            } else {
                vec![presentation_str
                    .parse()
                    .map_err(|e: identity_credential::sd_jwt_payload::Error| {
                        VpTokenValidationError::SdJwtParsingError(e.to_string())
                    })?]
            };

            for sd_jwt in sd_jwts {
                let decoded_vc_sd_jwt = self.validate_vcdm2_sd_jwt(&sd_jwt).await?;

                let obj = serde_json::to_value(decoded_vc_sd_jwt)?
                    .as_object()
                    .cloned()
                    .ok_or(VpTokenValidationError::InvalidDecodedCredentialType)?;
                decoded_credentials.push(obj);
            }
        }
        Ok(decoded_credentials)
    }

    /// Internal helper to validate a generic JWT presentation (signature, audience, nonce).
    async fn validate_presentation_jwt<CRED>(
        &self,
        presentation_jwt: &Jwt,
        client_id: &str,
        nonce: Option<&str>,
    ) -> Result<DecodedJwtPresentation<CRED>, VpTokenValidationError>
    where
        CRED: Serialize + DeserializeOwned + Clone,
    {
        // 1. Decode header to find KID
        let validation_item = Decoder::new()
            .decode_compact_serialization(presentation_jwt.as_str().as_bytes(), None)
            .map_err(VpTokenValidationError::JwsDecodingError)?;

        let kid_str = validation_item.kid().ok_or(VpTokenValidationError::MissingKid)?;
        let kid: DIDUrl = kid_str
            .parse()
            .map_err(|e: identity_did::Error| VpTokenValidationError::InvalidKid(e.to_string()))?;

        // 2. Resolve Holder's DID Document
        let resolver = &self.verification_material_resolver;

        let holder = resolver
            .resolve_did_document(kid.did())
            .await
            .map_err(|e| VpTokenValidationError::VerificationMaterialResolutionError(e.to_string()))?;

        // 3. Verify Signature
        let options = &Default::default();

        let decoded_jwt_presentation = self
            .jwt_presentation_validator
            .validate(presentation_jwt, &holder, options)?;

        // 4. Check Audience
        let aud = decoded_jwt_presentation.aud.as_ref().map(|aud| aud.to_string());

        if aud != Some(client_id.to_string()) {
            return Err(VpTokenValidationError::InvalidAudience {
                expected: Some(client_id.to_string()),
                found: aud,
            });
        }

        // 5. Check Nonce (if provided)
        if nonce.is_some() {
            let custom_claims = decoded_jwt_presentation
                .custom_claims
                .as_ref()
                .ok_or(VpTokenValidationError::MissingCustomClaims)?;

            let jwt_nonce = custom_claims.get("nonce").and_then(|v| v.as_str());
            if jwt_nonce != nonce {
                return Err(VpTokenValidationError::InvalidNonce {
                    expected: nonce.map(String::from),
                    found: jwt_nonce.map(String::from),
                });
            }
        }

        Ok(decoded_jwt_presentation)
    }

    /// Internal helper to validate a credential JWT.
    async fn validate_credential_jwt(
        &self,
        credential_jwt: &Jwt,
    ) -> Result<DecodedJwtCredential<JsonObject>, VpTokenValidationError> {
        let validation_item = Decoder::new()
            .decode_compact_serialization(credential_jwt.as_str().as_bytes(), None)
            .map_err(VpTokenValidationError::JwsDecodingError)?;

        let kid_str = validation_item.kid().ok_or(VpTokenValidationError::MissingKid)?;
        let kid: DIDUrl = kid_str
            .parse()
            .map_err(|e: identity_did::Error| VpTokenValidationError::InvalidKid(e.to_string()))?;

        let resolver = &self.verification_material_resolver;

        // TODO: verify whether issuer is trusted (through `trusted_authorities`).
        let issuer = resolver
            .resolve_did_document(kid.did())
            .await
            .map_err(|e| VpTokenValidationError::VerificationMaterialResolutionError(e.to_string()))?;

        // `SkipUnsupported` allows for custom credential types, such as the StatusList2021Entry (https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021entry)
        let options = &JwtCredentialValidationOptions::new().status_check(StatusCheck::SkipUnsupported);
        let fail_fast = FailFast::FirstError;

        let jwt_data = self
            .jwt_credential_validator
            .validate(credential_jwt, &issuer, options, fail_fast)
            .map_err(VpTokenValidationError::CredentialValidation)?;

        if let Some(status_claim) = jwt_data.custom_claims.as_ref().and_then(|v| v.get("status").cloned()) {
            match self.check_jwt_status_claim(status_claim).await {
                Ok(_) => {}
                Err(VpTokenValidationError::FailedToGetCredentialStatus(_)) => {} // If we fail to get the credential status we proceed the same as if there was no status claim
                Err(e) => return Err(e),
            };
        }

        Ok(jwt_data)
    }

    /// Internal helper to validate a generic SD-JWT VC (signature, key binding, disclosures).
    async fn validate_sd_jwt_vc(
        &self,
        sd_jwt_vc: &SdJwtVc,
        client_id: &str,
        nonce: Option<&str>,
        require_holder_binding: bool,
    ) -> Result<JsonObject, VpTokenValidationError> {
        let kid_str = sd_jwt_vc
            .headers()
            .get("kid")
            .ok_or(VpTokenValidationError::MissingKid)?
            .as_str()
            .ok_or_else(|| VpTokenValidationError::InvalidKid("kid header is not a string".to_string()))?;

        let kid: DIDUrl = kid_str
            .parse()
            .map_err(|e: identity_did::Error| VpTokenValidationError::InvalidKid(e.to_string()))?;

        let resolver = &self.verification_material_resolver;

        // TODO: verify whether issuer is trusted (through `trusted_authorities`).
        let _issuer = resolver
            .resolve_did_document(kid.did())
            .await
            .map_err(|e| VpTokenValidationError::VerificationMaterialResolutionError(e.to_string()))?;

        let public_key_jwk = resolver
            .resolve_public_key(&kid.to_string())
            .await
            .map_err(|e| VpTokenValidationError::VerificationMaterialResolutionError(e.to_string()))?;

        // 1. Verify Issuer Signature
        sd_jwt_vc
            .verify_signature(self.signature_verifier, &public_key_jwk)
            .map_err(|e| VpTokenValidationError::SdJwtValidation(e.to_string()))?;

        // 2. Verify Key Binding (Holder Binding) if required
        if require_holder_binding {
            if let Some(key_binding_jwt) = sd_jwt_vc.key_binding_jwt() {
                if key_binding_jwt.claims().aud != client_id {
                    return Err(VpTokenValidationError::InvalidAudience {
                        expected: Some(client_id.to_string()),
                        found: Some(key_binding_jwt.claims().aud.clone()),
                    });
                }

                if let Some(nonce) = nonce {
                    if key_binding_jwt.claims().nonce != nonce {
                        return Err(VpTokenValidationError::InvalidNonce {
                            expected: Some(nonce.to_string()),
                            found: Some(key_binding_jwt.claims().nonce.clone()),
                        });
                    }
                }
            } else {
                return Err(VpTokenValidationError::MissingHolderBinding);
            }
        }

        if let Some(status_claim) = &sd_jwt_vc.claims().status {
            let status_value = serde_json::to_value(status_claim)
                .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;
            match self.check_jwt_status_claim(status_value).await {
                Ok(_) => {}
                Err(VpTokenValidationError::FailedToGetCredentialStatus(_)) => {} // If we fail to get the credential status we proceed the same as if there was no status claim
                Err(e) => return Err(e),
            };
        }

        sd_jwt_vc
            .clone()
            .into_disclosed_object(&Sha256Hasher)
            .map_err(|e| VpTokenValidationError::SdJwtValidation(e.to_string()))
    }

    /// Internal helper to validate VCDM 2.0 SD-JWT.
    async fn validate_vcdm2_sd_jwt(&self, vcdm2_sd_jwt: &SdJwt) -> Result<CredentialV2, VpTokenValidationError> {
        let kid_str = vcdm2_sd_jwt
            .headers()
            .get("kid")
            .ok_or(VpTokenValidationError::MissingKid)?
            .as_str()
            .ok_or_else(|| VpTokenValidationError::InvalidKid("kid header is not a string".to_string()))?;

        let kid: DIDUrl = kid_str
            .parse()
            .map_err(|e: identity_did::Error| VpTokenValidationError::InvalidKid(e.to_string()))?;

        let resolver = &self.verification_material_resolver;

        // TODO: verify whether issuer is trusted (through `trusted_authorities`).
        let issuer = resolver
            .resolve_did_document(kid.did())
            .await
            .map_err(|e| VpTokenValidationError::VerificationMaterialResolutionError(e.to_string()))?;

        // `SkipUnsupported` allows for custom credential types, such as the StatusList2021Entry (https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021entry)
        let options = &JwtCredentialValidationOptions::new().status_check(StatusCheck::SkipUnsupported);

        let claims_value = serde_json::to_value(vcdm2_sd_jwt.claims())
            .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;
        if let Some(status_value) = claims_value.get("status").cloned() {
            match self.check_jwt_status_claim(status_value).await {
                Ok(_) => {}
                Err(VpTokenValidationError::FailedToGetCredentialStatus(_)) => {} // If we fail to get the credential status we proceed the same as if there was no status claim
                Err(e) => return Err(e),
            };
        }

        self.sd_jwt_credential_validator
            .validate_credential_v2(vcdm2_sd_jwt, &[issuer], options)
            .map_err(|e| VpTokenValidationError::SdJwtValidation(e.to_string()))
    }

    async fn check_jwt_status_claim(&self, status_claim: serde_json::Value) -> Result<(), VpTokenValidationError> {
        let idx = status_claim
            .get("idx")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let uri = status_claim
            .get("uri")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        if let (Some(idx), Some(uri)) = (idx, uri) {
            let status_list_jwt = fetch_status_list(
                &uri,
                StatusListTokenResponseType::Jwt, // TODO: the response type is hardcoded to be JWT, since we can't handle CWT yet. However when we implement CWT we then need some way to discover what encoding the Status List Provider is using.
            )
            .await?;

            let jwt_header = decode_header(&status_list_jwt)
                .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;
            let kid = jwt_header
                .kid
                .ok_or(VpTokenValidationError::FailedToGetCredentialStatus(
                    "No KID found".to_string(),
                ))?;
            let public_key_jwk = self
                .verification_material_resolver
                .resolve_public_key(&kid)
                .await
                .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;
            // Convert the `IotaIdentityJwk` first into a `JsonWebTokenJwk` and then into a `DecodingKey`.
            let decoding_key = public_key_jwk
                .to_json()
                .ok()
                .and_then(|public_key| JsonWebTokenJwk::from_json(&public_key).ok())
                .and_then(|jwk| DecodingKey::from_jwk(&jwk).ok())
                .ok_or(VpTokenValidationError::FailedToGetCredentialStatus(
                    "Failed to create decoding key".to_string(),
                ))?;

            let decoded_jwt = decrypt_status_list_token(&status_list_jwt, decoding_key)
                .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;

            let status_list: StatusList = decoded_jwt.claims.encoded_status_list.try_into().map_err(|_| {
                VpTokenValidationError::FailedToGetCredentialStatus("Failed to decode status list".to_string())
            })?;

            let index = idx.parse::<usize>().map_err(|_| {
                VpTokenValidationError::FailedToGetCredentialStatus(format!("Not a valid index: {}", idx))
            })?;
            let status = StatusType::try_from(status_list.get_status(index).map_err(|_| {
                VpTokenValidationError::FailedToGetCredentialStatus(
                    "Failed to get credential status from index".to_string(),
                )
            })?)
            .map_err(|_| {
                VpTokenValidationError::FailedToGetCredentialStatus(
                    "Failed to get credential status from index".to_string(),
                )
            })?;

            match status {
                StatusType::VALID => {} // do nothing, credential is valid
                _ => return Err(VpTokenValidationError::CredentialStatusInvalid),
            }
        }

        Ok(())
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

// Helper

/// Sends a status list request to the provided URI and returns the response body as a String.
/// The `accept_header` parameter determines the expected response format (e.g., JWT, compressed JWT).
/// If the response is gzip encoded, it will be decompressed before being returned.
pub async fn fetch_status_list(
    uri: &str,
    accept_header: StatusListTokenResponseType,
) -> Result<String, VpTokenValidationError> {
    // 3xx redirects should be followed, but infinite loops are caught after 5 redirects.
    // The timeout of 10 seconds is an estimated guess of how long a status list request should take at maximum.
    let client = Client::builder()
        .redirect(Policy::limited(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;

    let res = client
        .get(uri)
        .header(header::ACCEPT, accept_header.to_string())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;

    let is_gzipped = res
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|encoding| encoding == "gzip");

    let bytes = res
        .bytes()
        .await
        .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))?;

    if is_gzipped {
        decompress_gzip(&bytes).map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))
    } else {
        String::from_utf8(bytes.to_vec())
            .map_err(|e| VpTokenValidationError::FailedToGetCredentialStatus(e.to_string()))
    }
}

// TODO: We need to add credential signing functionality to `VpTokenBuilder` in order to have more thorough tests for the validator. For now, we are using pre-generated JWTs and SD-JWTs.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dcql::dcql_query::{ClaimQuery, CredentialQuery, MetaTypes},
        token::vp_token::Presentations,
    };
    use oid4vc_core::{
        claim_path_pointer::{ClaimPathElement, ClaimPathPointer},
        verification_material_resolver::test_utils::TestVerificationMaterialResolver,
        verifier::SignatureVerifier,
    };

    const VALID_JWT_VC_JSON_CREDENTIAL: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkI3o2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCIsInN1YiI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkIiwiYXVkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ejZNa2V1cGVQVktpa0x2NEtYRTk5b0F2UWJnQVI3cVhxM0FHVXRzU2VvcVpnRkJWIiwiZXhwIjo3ODIxMjQ3MjUxLCJpYXQiOjE3NzMyNDcyNTEsInZwIjp7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiIsInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SjBlWEFpT2lKS1YxUWlMQ0poYkdjaU9pSkZaRVJUUVNJc0ltdHBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyVjFjR1ZRVmt0cGEweDJORXRZUlRrNWIwRjJVV0puUVZJM2NWaHhNMEZIVlhSelUyVnZjVnBuUmtKV0kzbzJUV3RsZFhCbFVGWkxhV3RNZGpSTFdFVTVPVzlCZGxGaVowRlNOM0ZZY1ROQlIxVjBjMU5sYjNGYVowWkNWaUo5LmV5SnBjM01pT2lKa2FXUTZhMlY1T25vMlRXdGxkWEJsVUZaTGFXdE1kalJMV0VVNU9XOUJkbEZpWjBGU04zRlljVE5CUjFWMGMxTmxiM0ZhWjBaQ1ZpSXNJbk4xWWlJNkltUnBaRHByWlhrNmVqWk5hMmc1ZVRSTVUwWTRNbTlXY2swM1MzcHhaaloxT0ZWdk1VNTFVRmx5VW01a00yOTNRa3hGUlVGRVRIQmtJaXdpYm1KbUlqb3hOemN6TWpRM01qSTRMQ0pwWVhRaU9qRTNOek15TkRjeU1qZ3NJblpqSWpwN0ltTnlaV1JsYm5ScFlXeFRkV0pxWldOMElqcDdJbVpwY25OMFgyNWhiV1VpT2lKR1pYSnlhWE1pTENKc1lYTjBYMjVoYldVaU9pSkRjbUZpYldGdUlpd2laRzlpSWpvaU1UazRNaTB3TVMwd01TSXNJbWxrSWpvaVpHbGtPbXRsZVRwNk5rMXJhRGw1TkV4VFJqZ3liMVp5VFRkTGVuRm1OblU0Vlc4eFRuVlFXWEpTYm1RemIzZENURVZGUVVSTWNHUWlmU3dpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNKZExDSnBjM04xWlhJaU9uc2libUZ0WlNJNklsVnVhVU52Y21VaUxDSnBaQ0k2SW1ScFpEcHJaWGs2ZWpaTmEyVjFjR1ZRVmt0cGEweDJORXRZUlRrNWIwRjJVV0puUVZJM2NWaHhNMEZIVlhSelUyVnZjVnBuUmtKV0luMHNJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPaTh2ZDNkM0xuY3pMbTl5Wnk4eU1ERTRMMk55WldSbGJuUnBZV3h6TDNZeElsMHNJbWx6YzNWaGJtTmxSR0YwWlNJNklqSXdNall0TURNdE1URlVNVFk2TkRBNk1qaGFJaXdpZG1Gc2FXUkdjbTl0SWpvaU1qQXlOaTB3TXkweE1WUXhOam8wTURveU9Gb2lMQ0pqY21Wa1pXNTBhV0ZzVTNSaGRIVnpJanA3SW5SNWNHVWlPaUp6ZEdGMGRYTnNhWE4wSzJwM2RDSXNJbWxrSWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvek1ETXpMMmxsZEdZdGIyRjFkR2d0ZEc5clpXNHRjM1JoZEhWekxXeHBjM1F2TVNJc0luVnlhU0k2SW1oMGRIQTZMeTlzYjJOaGJHaHZjM1E2TXpBek15OXBaWFJtTFc5aGRYUm9MWFJ2YTJWdUxYTjBZWFIxY3kxc2FYTjBMekVpTENKcFpIZ2lPamd3TkRoOWZTd2ljM1JoZEhWeklqcDdJbk4wWVhSMWMxOXNhWE4wSWpwN0luVnlhU0k2SW1oMGRIQTZMeTlzYjJOaGJHaHZjM1E2TXpBek15OXBaWFJtTFc5aGRYUm9MWFJ2YTJWdUxYTjBZWFIxY3kxc2FYTjBMekVpTENKcFpIZ2lPamd3TkRoOWZYMC5fS2lDZUVtZmFfVFFXaVNOTk9hWHZfV3FKNkM5ZkNtLVZTUE53NzVNLVBQS1ZYSGtiNlJiM1lGS25DSVo3M1ZGUVBibWVrX0RwV2F5WWVWTm55NjNBZyJdLCJob2xkZXIiOiJkaWQ6a2V5Ono2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCJ9LCJub25jZSI6ImJlMWExYjIwMDg0ZjY1NjYwMzNkZTdiYzJmOTBiODM3NzIyZmVhYjRhYjZhZjcxY2VjYjg5ZmY0Mjc0NWFiY2QifQ.59V_DEJ2R75iymoUOC67fN2sWvC_W4KaqeDEvamYjbWe-gTHikTzoyH3zxhjj-YbCWhOibQNeSDf8ELn1lCSAg";
    const VALID_DC_SD_JWT_CREDENTIAL: &str = "eyJ0eXAiOiJkYytzZC1qd3QiLCJraWQiOiJkaWQ6a2V5Ono2TWtldXBlUFZLaWtMdjRLWEU5OW9BdlFiZ0FSN3FYcTNBR1V0c1Nlb3FaZ0ZCViN6Nk1rZXVwZVBWS2lrTHY0S1hFOTlvQXZRYmdBUjdxWHEzQUdVdHNTZW9xWmdGQlYiLCJhbGciOiJFZERTQSJ9.eyJ2Y3QiOiJodHRwOi8vbG9jYWxob3N0OjMwMzMvdmN0L1UwUXRTbGRVSUZaRC8wIiwiX3NkIjpbIjhWRjlEYkRnaDJrT0kwWW5Cc0dBQUJuTldIZ1puVWlQOENZVjBRMTFmc00iLCJZSUh1ZDNuUHRDV3c1NkY2OWNLYU1NWDNsOGd1UFgwbVNUcDVPSV9QNVo4IiwidWhpSHdOaUtrQUJDN2tBQUxzU0ZMM0JaeXJnb05McnRGTGNXOHg2SWdwMCJdLCJpc3MiOiJkaWQ6a2V5Ono2TWtldXBlUFZLaWtMdjRLWEU5OW9BdlFiZ0FSN3FYcTNBR1V0c1Nlb3FaZ0ZCViIsIm5iZiI6MTc3MzI0NzQxMywiaWF0IjoxNzczMjQ3NDEzLCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsidXJpIjoiaHR0cDovL2xvY2FsaG9zdDozMDMzL2lldGYtb2F1dGgtdG9rZW4tc3RhdHVzLWxpc3QvMCIsImlkeCI6Mzk3N319LCJfc2RfYWxnIjoic2hhLTI1NiIsImNuZiI6eyJraWQiOiJkaWQ6a2V5Ono2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCN6Nk1raDl5NExTRjgyb1ZyTTdLenFmNnU4VW8xTnVQWXJSbmQzb3dCTEVFQURMcGQifX0.-yfZPKWJbeRE45GPqzFIT-wB-f1jXstqR9puEpnobWhY3Ddxf7z1HtZMb4GJcvbOrtcako9ptSxc8keIR-XADw~WyJKbjhUbUh4QmZwLXItd3dCX2h6UEFiS214aEt2R3NMZXJfazBlS21OIiwiZmlyc3RfbmFtZSIsIkZlcnJpcyJd~WyJua0ZZSzV5enZvT0l4c245aF9xcjdHNzJqS2M2ZXo4OVRQZmExb3RYIiwibGFzdF9uYW1lIiwiQ3JhYm1hbiJd~WyJGOUZsRHZ6X0EtbzJuYWw1TzJfaDdoRkQ3MFZTMHlQNFhnczdDQ1U0IiwiZG9iIiwiMTk4Mi0wMS0wMSJd~eyJhbGciOiJSUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NzMyNDc0OTEsImF1ZCI6ImRlY2VudHJhbGl6ZWRfaWRlbnRpZmllcjpkaWQ6a2V5Ono2TWtldXBlUFZLaWtMdjRLWEU5OW9BdlFiZ0FSN3FYcTNBR1V0c1Nlb3FaZ0ZCViIsIm5vbmNlIjoiMWMyYzY4NjRhM2Y0ZTMzNTcxMmJiNzg5MDI0OWQzYzQ2ZTE3N2RkNjJlM2U5M2JjM2E0ZDA4YWNkZTdkNGFiNCIsInNkX2hhc2giOiJidHdZSFU5Rjd5Q2liNDZDN0pWaElwa2pHTUxER2xZeGFvTmZab2NsSzZrIn0.AcganwldnIvrZd_4ube0es_NLo-A8mRo6XL-z0sRkE4Sp9XgeqyLV_0FK6Nx8TWk1zcd3xYZS7eAQWdU3JLcDg";
    const VALID_VC_SD_JWT_CREDENTIAL: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkI3o2TWtoOXk0TFNGODJvVnJNN0t6cWY2dThVbzFOdVBZclJuZDNvd0JMRUVBRExwZCJ9.eyJAY29udGV4dCI6Imh0dHBzOi8vd3d3LnczLm9yZy9ucy9jcmVkZW50aWFscy92MiIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7IkBjb250ZXh0IjoiaHR0cHM6Ly93d3cudzMub3JnL25zL2NyZWRlbnRpYWxzL3YyIiwiaWQiOiJkYXRhOmFwcGxpY2F0aW9uL3ZjK3NkLWp3dCxleUowZVhBaU9pSjJZeXR6WkMxcWQzUWlMQ0pyYVdRaU9pSmthV1E2YTJWNU9ubzJUV3RsZFhCbFVGWkxhV3RNZGpSTFdFVTVPVzlCZGxGaVowRlNOM0ZZY1ROQlIxVjBjMU5sYjNGYVowWkNWaU42TmsxclpYVndaVkJXUzJsclRIWTBTMWhGT1RsdlFYWlJZbWRCVWpkeFdIRXpRVWRWZEhOVFpXOXhXbWRHUWxZaUxDSmhiR2NpT2lKRlpFUlRRU0o5LmV5SmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUpmYzJRaU9sc2lSa1JaYzNkemFTMTVlREJoUWtOb2VrVmZiVVJxU21GMmJIRnNUVkZMYmtOSk9HWlpabk5JUjFZMVNTSXNJa3RZYURWdWVXWmtNMUJrZEZWSWNXTXRaSFpvTFhSSWQybDNhMUF5Ym1SaFUzUTNla1ZETkVSSFlrMGlMQ0pQVTFWSVlVdzVhMVpLTUZGclVWUkpkRVZ3VG5aTlowRkJXbTB6UWxoR2NqbHJRMmRqTkVKUmVGZE5JaXdpVlZWM2FISTBURVZzYzNkeVh6QktSSEEzYkZCU2NVdHRRWFYzZWpOT1FWZ3phWGxoWWxKeWNqRm9ieUpkZlN3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSmRMQ0p1WVcxbElqb2lWa05FVFNBeUxqQWdVMFF0U2xkVUlFTnlaV1JsYm5ScFlXd2lMQ0pwYzNOMVpYSWlPbnNpYm1GdFpTSTZJbFZ1YVVOdmNtVWlMQ0pwWkNJNkltUnBaRHByWlhrNmVqWk5hMlYxY0dWUVZrdHBhMHgyTkV0WVJUazViMEYyVVdKblFWSTNjVmh4TTBGSFZYUnpVMlZ2Y1ZwblJrSldJbjBzSWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OXVjeTlqY21Wa1pXNTBhV0ZzY3k5Mk1pSmRMQ0pwYzNOMVlXNWpaVVJoZEdVaU9pSXlNREkyTFRBekxURXhWREUyT2pRNU9qVTJXaUlzSW5aaGJHbGtSbkp2YlNJNklqSXdNall0TURNdE1URlVNVFk2TkRrNk5UWmFJaXdpWTNKbFpHVnVkR2xoYkZOMFlYUjFjeUk2ZXlKMGVYQmxJam9pYzNSaGRIVnpiR2x6ZEN0cWQzUWlMQ0pwWkNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk16QXpNeTlwWlhSbUxXOWhkWFJvTFhSdmEyVnVMWE4wWVhSMWN5MXNhWE4wTHpBaUxDSjFjbWtpT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pNd016TXZhV1YwWmkxdllYVjBhQzEwYjJ0bGJpMXpkR0YwZFhNdGJHbHpkQzh3SWl3aWFXUjRJam94T0RaOUxDSnpkR0YwZFhNaU9uc2ljM1JoZEhWelgyeHBjM1FpT25zaWRYSnBJam9pYUhSMGNEb3ZMMnh2WTJGc2FHOXpkRG96TURNekwybGxkR1l0YjJGMWRHZ3RkRzlyWlc0dGMzUmhkSFZ6TFd4cGMzUXZNQ0lzSW1sa2VDSTZNVGcyZlgwc0ltbHpjeUk2SW1ScFpEcHJaWGs2ZWpaTmEyVjFjR1ZRVmt0cGEweDJORXRZUlRrNWIwRjJVV0puUVZJM2NWaHhNMEZIVlhSelUyVnZjVnBuUmtKV0lpd2lYM05rWDJGc1p5STZJbk5vWVMweU5UWWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaVpHbGtPbXRsZVRwNk5rMXJhRGw1TkV4VFJqZ3liMVp5VFRkTGVuRm1OblU0Vlc4eFRuVlFXWEpTYm1RemIzZENURVZGUVVSTWNHUWplalpOYTJnNWVUUk1VMFk0TW05V2NrMDNTM3B4WmpaMU9GVnZNVTUxVUZseVVtNWtNMjkzUWt4RlJVRkVUSEJrSW4xOS5yLVFneXVTNGZlUk5ob3haWHctb2NEQ1NWSzR5S29uZUl1SV9nbks5X3JEVUVlR0lFRnZ3Y0pmQ09FYUtXMVF0OG5FZ0ZzSl80UjVJRFZCRmJKck5EZ35XeUpTU1VoeFJuSm5XR1Z5Y2t0bk4xTmhVMDVXZDNsM2FITmtlVFJrUlZaM1lWVlJTV0pTV1ROTklpd2labWx5YzNSZmJtRnRaU0lzSWtabGNuSnBjeUpkfld5SmhPVGx3VTBoQlIzbE5VbVZOYW5ablRFOUJTVXhXWmw5UFpHbFBUMUZGYldwcFQzcFRhREY0SWl3aWJHRnpkRjl1WVcxbElpd2lRM0poWW0xaGJpSmR-V3lKSFNqZFVabEZxZEdKU1VYSnlPR05WVEdKRlZITlBkMGRqWlhOd2NsRTBkM05xUWxOa01tcFlJaXdpWkc5aUlpd2lNVGs0TWkwd01TMHdNU0pkfld5Sk1kMVZvWDNBMWNqbHZUM2RtVVV4NVZFTm1TbXA0YzJWTU5ERnVORkZUT1VGa1gydGFlVjlWSWl3aWFXUWlMQ0prYVdRNmEyVjVPbm8yVFd0b09YazBURk5HT0RKdlZuSk5OMHQ2Y1dZMmRUaFZiekZPZFZCWmNsSnVaRE52ZDBKTVJVVkJSRXh3WkNKZH4iLCJ0eXBlIjoiRW52ZWxvcGVkVmVyaWZpYWJsZUNyZWRlbnRpYWwifV0sImhvbGRlciI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkIiwiYXVkIjoiZGVjZW50cmFsaXplZF9pZGVudGlmaWVyOmRpZDprZXk6ejZNa2V1cGVQVktpa0x2NEtYRTk5b0F2UWJnQVI3cVhxM0FHVXRzU2VvcVpnRkJWIiwiZXhwIjo3ODIxMjQ4MjA2LCJpYXQiOjE3NzMyNDgyMDYsImlzcyI6ImRpZDprZXk6ejZNa2g5eTRMU0Y4Mm9Wck03S3pxZjZ1OFVvMU51UFlyUm5kM293QkxFRUFETHBkIiwibm9uY2UiOiI4ZGY5MWE0YTE5Y2IxYmFiZGE4YmI1OTlhYmU1MmNhZWFlNWFhODgxOWYzOGQ3NjJkMTM0NDZhZGQ3YmQwOWY0In0.t8Q4bmZAD2hFcQxLQfKWM21yOnzr-syra6fGgh9IuDzXEbm_J4ZiJ6YoD8b7eQkB431TDuRGzx57oEAkD8YgCA";

    #[tokio::test]
    async fn test_validate_vp_token_with_jwt_vc_json() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::JwtVcJson,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        ClaimPathElement::String("first_name".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                Presentations::try_new(vec![VALID_JWT_VC_JSON_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    Some("be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd"),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_vp_token_with_dc_sd_jwt() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::DcSdJwt,
                multiple: None,
                meta: MetaTypes::SdJwtMeta {
                    vct_values: vec!["http://localhost:3033/vct/U0QtSldU/0".to_string()],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![ClaimPathElement::String("first_name".to_string())]).unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                Presentations::try_new(vec![VALID_DC_SD_JWT_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    Some("1c2c6864a3f4e335712bb7890249d3c46e177dd62e3e93bc3a4d08acde7d4ab4"),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_validate_vp_token_with_vc_sd_jwt() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::VcSdJwt,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        ClaimPathElement::String("first_name".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                Presentations::try_new(vec![VALID_VC_SD_JWT_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    Some("8df91a4a19cb1babda8bb599abe52caeae5aa8819f38d762d13446add7bd09f4"),
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn missing_credential_claim_results_in_dcql_evaluation_fail() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::JwtVcJson,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        // This claim does not exist in the credential, so the DCQL evaluation should fail
                        ClaimPathElement::String("different_claim".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                Presentations::try_new(vec![VALID_JWT_VC_JSON_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    Some("be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd"),
                )
                .await
                .unwrap_err(),
            // The JWT VC JSON credential is valid, but the claim query is looking for a claim that does not exist in the credential, so the DCQL evaluation should fail
            VpTokenValidationError::DcqlEvaluationFailed
        ));
    }

    #[tokio::test]
    async fn nonce_mismatch_results_in_invalid_nonce_error() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::JwtVcJson,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        ClaimPathElement::String("first_name".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                Presentations::try_new(vec![VALID_JWT_VC_JSON_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    // This nonce does not match the one in the VP token.
                    Some("different nonce that does not match the one in the VP token"),
                )
                .await
                .unwrap_err(),
            // The JWT VC JSON credential is valid and the claim query is looking for a claim that exists in the
            // credential, but the nonce does not match the one in the VP token, so the validation should fail with an
            // InvalidNonce error.
            VpTokenValidationError::InvalidNonce { .. }
        ));
    }

    #[tokio::test]
    async fn wrong_credential_format_results_in_presentation_validation_error() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                // This DCQL query is looking for a VC SD-JWT credential, but the VP token will contain a JWT VC JSON
                // credential.
                format: Format::VcSdJwt,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        ClaimPathElement::String("first_name".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                // The VP token contains a JWT VC JSON credential, but the DCQL query is looking for a VC SD-JWT
                // credential.
                Presentations::try_new(vec![VALID_JWT_VC_JSON_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    Some("be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd"),
                )
                .await
                .unwrap_err(),
            // The JWT VC JSON credential is valid and the nonce matches, but the DCQL query is looking for a VC SD-JWT
            // credential, so the validation should fail with a PresentationValidation error indicating that the
            // credential format does not match the expected format.
            VpTokenValidationError::PresentationValidation(_)
        ));
    }

    #[tokio::test]
    async fn client_id_mismatch_results_in_invalid_audience_error() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::JwtVcJson,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        ClaimPathElement::String("first_name".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                CredentialQueryId::try_new("CredentialQuery").unwrap(),
                Presentations::try_new(vec![VALID_JWT_VC_JSON_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    // The VP token is valid and the claim query is looking for a claim that exists in the credential,
                    // but the client ID (audience) does not match the one in the VP token, so the validation should
                    // fail with an InvalidAudience error.
                    "decentralized_identifier:did:key:z6MkiTcXZ1JxooACo99YcfkugH6Kifzj7ZupSDCmLEABpjpF",
                    Some("be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd"),
                )
                .await
                .unwrap_err(),
            VpTokenValidationError::InvalidAudience { .. }
        ));
    }

    #[tokio::test]
    async fn credential_query_id_mismatch_results_in_presentation_submission_validation_error() {
        let dcql_query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: CredentialQueryId::try_new("CredentialQuery").unwrap(),
                format: Format::JwtVcJson,
                multiple: None,
                meta: MetaTypes::W3CFormatMeta {
                    type_values: vec![vec!["VerifiableCredential".to_string()]],
                },
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
                claims: Some(vec![ClaimQuery {
                    id: None,
                    path: ClaimPathPointer::try_new(vec![
                        ClaimPathElement::String("credentialSubject".to_string()),
                        ClaimPathElement::String("first_name".to_string()),
                    ])
                    .unwrap(),
                    values: None,
                }]),
                claim_sets: None,
            }],
            credential_sets: None,
        };

        let vp_token = VpToken::builder()
            .add_presentations(
                // The VP token contains a presentation for a Credential Query with a different ID:
                // "DifferentCredentialQueryID".
                CredentialQueryId::try_new("DifferentCredentialQueryID").unwrap(),
                Presentations::try_new(vec![VALID_JWT_VC_JSON_CREDENTIAL.into()]).unwrap(),
            )
            .build()
            .unwrap();

        assert!(matches!(
            VpTokenValidator::new(&SignatureVerifier, &TestVerificationMaterialResolver)
                .validate_vp_token(
                    &dcql_query,
                    &vp_token,
                    "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV",
                    Some("be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd"),
                )
                .await
                .unwrap_err(),
            // The JWT VC JSON credential is valid, the nonce matches, and the client ID matches, but the VP token
            // contains a presentation for a Credential Query with a different ID than the one in the DCQL query, so
            // the validation should fail with a MissingRequiredCredential error indicating that there is no
            // presentation in the VP token for the Credential Query in the DCQL query.
            VpTokenValidationError::PresentationSubmissionValidation(VpTokenBuilderError::MissingRequiredCredential(_))
        ));
    }
}
