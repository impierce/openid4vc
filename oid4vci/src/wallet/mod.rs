use crate::Proof;
use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::{AuthorizationRequest, CodeChallengeMethod};
use crate::authorization_response::AuthorizationResponse;
use crate::credential_issuer::credential_configurations_supported::{
    AlgIdentifier, CredentialConfigurationsSupportedObject,
};
use crate::credential_issuer::{
    authorization_server_metadata::AuthorizationServerMetadata, credential_issuer_metadata::CredentialIssuerMetadata,
};
use crate::credential_offer::CredentialOfferParameters;
use crate::credential_request::{CredentialIdentifierOrCredentialConfigurationId, CredentialRequest};
use crate::interactive_authorization_request::{
    InteractionType, InteractiveAuthorizationFollowUpRequest, InteractiveAuthorizationRequest,
};
use crate::interactive_authorization_response::InteractiveAuthorizationResponse;
use crate::nonce_response::NonceResponse;
use crate::notification_request::{NotificationEvent, NotificationRequest};
use crate::proof::{ProofKeyReference, ProofType};
use crate::proofs::Proofs;
use crate::{credential_response::CredentialResponse, token_request::TokenRequest, token_response::TokenResponse};
use anyhow::{Result, anyhow};
use jsonwebtoken::Algorithm;
use oid4vc_core::SubjectSyntaxType;
use oid4vc_core::authentication::subject::SigningSubject;
use oid4vc_core::utils::form_urlencoded::to_form_urlencoded_string;
use reqwest::Url;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::RetryTransientMiddleware;
use reqwest_retry::policies::ExponentialBackoff;
use std::str::FromStr;

#[derive(Debug)]
pub struct Wallet {
    pub subject: SigningSubject,
    pub supported_subject_syntax_types: Vec<SubjectSyntaxType>,
    pub client: ClientWithMiddleware,
    pub proof_signing_alg_values_supported: Vec<Algorithm>,
}

// TODO: Move everything related to pushed authorization response to a separate module?
/// Successful Pushed Authorization Request response as defined by RFC 9126.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

// TODO: Move everything related to pushed authorization response to a separate module?
/// Query parameters used to submit an Authorization Request by reference.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct AuthorizationRequestByReference {
    pub client_id: String,
    pub request_uri: String,
}

impl Wallet {
    pub fn new(
        subject: SigningSubject,
        supported_subject_syntax_types: Vec<impl TryInto<SubjectSyntaxType>>,
        proof_signing_alg_values_supported: Vec<Algorithm>,
    ) -> anyhow::Result<Self> {
        let client = with_retries(oid4vc_core::http_client());
        Ok(Self {
            subject,
            supported_subject_syntax_types: supported_subject_syntax_types
                .into_iter()
                .map(|subject_syntax_type| {
                    subject_syntax_type
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Invalid did method."))
                })
                .collect::<Result<_>>()?,
            client,
            proof_signing_alg_values_supported,
        })
    }

    /// Sends this wallet's requests with `client` instead of [`oid4vc_core::http_client`], wrapped in the same retry
    /// middleware. For an application with a TLS policy of its own, such as pinned roots or a test CA in a debug build.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.client = with_retries(client);
        self
    }

    // Only the host of `credential_offer_uri` is logged: a plain GET on the full URI returns the Credential Offer,
    // including any `pre-authorized_code` (OID4VCI 1.0, Section 4.1.3), so the URI is as sensitive as that code.
    #[tracing::instrument(level = "debug", err, skip(self, credential_offer_uri))]
    pub async fn get_credential_offer(&self, credential_offer_uri: Url) -> Result<CredentialOfferParameters> {
        tracing::info!(
            credential_offer_host = credential_offer_uri.host_str().unwrap_or_default(),
            "Fetching credential offer"
        );
        tracing::trace!(%credential_offer_uri, "Credential offer URI");
        let response = self.client.get(credential_offer_uri).send().await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from credential offer endpoint: {e}"))?;
        tracing::trace!(%status, body = %text, "Credential offer response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Failed to get credential offer (HTTP {status}): {text}"
            ));
        }

        let offer: CredentialOfferParameters = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse credential offer (HTTP {status}, {} bytes): {e}",
                text.len()
            )
        })?;
        tracing::debug!(
            credential_issuer = %offer.credential_issuer,
            credential_configuration_ids = ?offer.credential_configuration_ids,
            "Received credential offer parameters"
        );
        Ok(offer)
    }

    #[tracing::instrument(level = "debug", err, skip(self))]
    pub async fn get_authorization_server_metadata(
        &self,
        credential_issuer_url: Url,
    ) -> Result<AuthorizationServerMetadata> {
        tracing::info!(%credential_issuer_url, "Fetching authorization server metadata");
        let mut oauth_authorization_server_endpoint = credential_issuer_url.clone();

        // According to RFC 8414, the path to the OAuth Authorization Server Metadata is formed by
        // appending `/.well-known/oauth-authorization-server` to the issuer's origin. If the issuer
        // URL contains a path, then that path must be appended to the well-known path.
        // See RFC 8414 Section 3: https://www.rfc-editor.org/rfc/rfc8414.html#section-3
        oauth_authorization_server_endpoint.set_path(&format!(
            "/.well-known/oauth-authorization-server{}",
            credential_issuer_url.path()
        ));

        oauth_authorization_server_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .pop_if_empty();

        tracing::debug!(%oauth_authorization_server_endpoint, "Trying RFC 8414 OAuth authorization server metadata endpoint");
        let response = self.client.get(oauth_authorization_server_endpoint).send().await;

        if let Ok(response) = response {
            let status = response.status();
            // If the request to the `oauth-authorization-server` endpoint is successful, return the metadata.
            if status.is_success() {
                let text = response.text().await.map_err(|e| {
                    anyhow::anyhow!("Failed to read response body from OAuth authorization server endpoint: {e}")
                })?;
                let metadata = serde_json::from_str::<AuthorizationServerMetadata>(&text).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to parse authorization server metadata (HTTP {status}): {e}. Raw response: {text}"
                    )
                })?;
                tracing::debug!(?metadata, "Successfully retrieved OAuth authorization server metadata");
                return Ok(metadata);
            }
        }

        // If the request to the `oauth-authorization-server` endpoint fails, fallback to the OpenID Provider Configuration endpoint.
        // See RFC 8414 Section 5: https://www.rfc-editor.org/rfc/rfc8414.html#section-5
        let mut openid_configuration_endpoint = credential_issuer_url.clone();

        openid_configuration_endpoint
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("unable to parse credential issuer url"))?
            .pop_if_empty()
            .push(".well-known")
            .push("openid-configuration");

        tracing::debug!(%openid_configuration_endpoint, "Trying fallback OpenID configuration endpoint");
        let response = self.client.get(openid_configuration_endpoint).send().await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from OpenID configuration endpoint: {e}"))?;

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Failed to get metadata from both primary and fallback endpoints (HTTP {status}): {text}"
            ));
        }

        let metadata = serde_json::from_str::<AuthorizationServerMetadata>(&text).map_err(|e| {
            anyhow::anyhow!("Failed to parse OpenID configuration metadata (HTTP {status}): {e}. Raw response: {text}")
        })?;
        tracing::debug!(?metadata, "Successfully retrieved OpenID configuration metadata");
        Ok(metadata)
    }

    #[tracing::instrument(level = "debug", err, skip(self))]
    pub async fn get_credential_issuer_metadata(&self, credential_issuer_url: Url) -> Result<CredentialIssuerMetadata> {
        tracing::info!(%credential_issuer_url, "Fetching credential issuer metadata");
        let mut openid_credential_issuer_endpoint = credential_issuer_url.clone();
        let path = credential_issuer_url.path().trim_end_matches('/');
        openid_credential_issuer_endpoint.set_path(&format!("/.well-known/openid-credential-issuer{path}"));

        tracing::debug!(%openid_credential_issuer_endpoint, "Requesting OpenID credential issuer metadata");
        let response = self.client.get(openid_credential_issuer_endpoint).send().await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from credential issuer endpoint: {e}"))?;

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Failed to get credential issuer metadata (HTTP {status}): {text}"
            ));
        }

        let metadata: CredentialIssuerMetadata = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!("Failed to parse credential issuer metadata (HTTP {status}): {e}. Raw response: {text}")
        })?;
        tracing::debug!(?metadata, "Successfully retrieved credential issuer metadata");
        Ok(metadata)
    }

    // TODO: Move everything related to pushed authorization response to a separate module?
    // TODO: refactor to reduce the number of arguments
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", err, skip(self, state, authorization_details, issuer_state))]
    pub async fn get_pushed_authorization_response(
        &self,
        pushed_authorization_request_endpoint: Url,
        client_id: &str,
        redirect_uri: Url,
        state: String,
        authorization_details: Option<Vec<AuthorizationDetailsObject>>,
        issuer_state: String,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
    ) -> Result<PushedAuthorizationResponse> {
        tracing::info!(%pushed_authorization_request_endpoint, %client_id, "Sending pushed authorization request (PAR)");
        let authorization_request = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: Some(redirect_uri),
            // TODO: add support for `scope`, see: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.4
            scope: None,
            state: Some(state),
            authorization_details,
            issuer_state: Some(issuer_state),
            code_challenge,
            code_challenge_method,
        };

        let url_encoded = to_form_urlencoded_string(&authorization_request)?;
        tracing::trace!(body = %url_encoded, "Pushed authorization request body");

        let response = self
            .client
            .post(pushed_authorization_request_endpoint)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(url_encoded)
            .send()
            .await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from PAR endpoint: {e}"))?;
        tracing::trace!(%status, body = %text, "Pushed authorization response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Pushed authorization request failed (HTTP {status}): {text}"
            ));
        }

        let par_response: PushedAuthorizationResponse = serde_json::from_str(&text).map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse pushed authorization response (HTTP {status}, {} bytes): {err}",
                text.len()
            )
        })?;
        tracing::debug!(
            expires_in = par_response.expires_in,
            "Received pushed authorization response"
        );
        Ok(par_response)
    }

    #[tracing::instrument(level = "debug", err, skip(self, _authorization_details))]
    pub async fn get_authorization_code(
        &self,
        authorization_endpoint: Url,
        _authorization_details: Vec<AuthorizationDetailsObject>,
        _code_challenge: Option<String>,
        _code_challenge_method: Option<String>,
        pushed_authorization_response: Option<PushedAuthorizationResponse>,
    ) -> Result<AuthorizationResponse> {
        let client_id = self
            .subject
            .identifier(
                &self
                    .supported_subject_syntax_types
                    .first()
                    .map(ToString::to_string)
                    .ok_or(anyhow!("No supported subject syntax types found."))?,
                self.proof_signing_alg_values_supported[0],
            )
            .await?;

        if let Some(pushed_response) = pushed_authorization_response {
            tracing::info!(%authorization_endpoint, %client_id, "Requesting authorization code using PAR request_uri");
            let authorization_request = AuthorizationRequestByReference {
                client_id,
                request_uri: pushed_response.request_uri,
            };

            return Ok(self
                .client
                .get(authorization_endpoint)
                .form(&authorization_request)
                .send()
                .await?
                .json::<AuthorizationResponse>()
                .await?);
        }

        // TODO: Support regular authorization request without pushed authorization request.
        Err(anyhow!(
            "Authorization code flow without pushed authorization request is not supported yet."
        ))
    }

    #[tracing::instrument(level = "debug", err, skip(self, token_request))]
    pub async fn get_access_token(&self, token_endpoint: Url, token_request: TokenRequest) -> Result<TokenResponse> {
        tracing::info!(%token_endpoint, "Sending token request to token endpoint");
        tracing::trace!(?token_request, "Token request");
        // Not `RequestBuilder::form`: `serde_urlencoded` cannot encode `authorization_details`, which goes as JSON.
        let url_encoded = to_form_urlencoded_string(&token_request)?;
        let response = self
            .client
            .post(token_endpoint)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(url_encoded)
            .send()
            .await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from token endpoint: {e}"))?;
        tracing::trace!(%status, body = %text, "Token response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!("Token request failed (HTTP {status}): {text}"));
        }

        let token_response: TokenResponse = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse token response (HTTP {status}, {} bytes): {e}",
                text.len()
            )
        })?;
        tracing::debug!("Successfully received token response");
        Ok(token_response)
    }

    // Select supported signing algorithm that matches the Credential Issuer's supported Proof Types.
    // Supplying the `proofs` parameter to the Credential Request is only required when the `proof_types_supported`
    // parameter is present in the Credential Configuration in the Credential Issuer's metadata. However, if the
    // `proof_types_supported` is not present, the Wallet will still provide the `proofs` signed with its own preferred
    // signing algorithm. For more information see: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request
    #[tracing::instrument(level = "debug", err, skip(self, credential_configuration))]
    fn select_signing_algorithm(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
        key_reference: ProofKeyReference,
    ) -> Result<Algorithm> {
        let proof_types_supported = &credential_configuration.proof_types_supported;

        // A proof that names its key by `jwk` carries the key itself, and only the keys of some algorithms can be
        // written as one: the Wallet's other algorithms are left out, in the Wallet's order of preference.
        let mut wallet_algorithms = self.proof_signing_alg_values_supported.iter().filter(|algorithm| {
            key_reference == ProofKeyReference::Kid || oid4vc_core::jwt::JWK_ALGORITHMS.contains(algorithm)
        });

        // If the Credential Issuer does not define any supported Proof Types, then the Wallet will use its own default signing algorithm.
        if proof_types_supported.is_empty() {
            let default_alg = wallet_algorithms
                .next()
                .ok_or(anyhow::anyhow!("Wallet does not support any signing algorithms"))
                .cloned()?;
            tracing::debug!(
                ?default_alg,
                "Issuer specified no proof types, using wallet default signing algorithm"
            );
            return Ok(default_alg);
        }

        // Extract the actual signing algorithms if the Credential Issuer supports JWT proof types.
        // TODO: support Proof types other than Jwt.
        let credential_issuer_proof_signing_alg_values_supported = proof_types_supported
            .get(&ProofType::Jwt)
            .map(|proof_type| proof_type.proof_signing_alg_values_supported.clone())
            .ok_or_else(|| anyhow::anyhow!("The Credential Issuer does not support JWT proof types"))?;

        tracing::debug!(
            wallet_algorithms = ?self.proof_signing_alg_values_supported,
            issuer_supported = ?credential_issuer_proof_signing_alg_values_supported,
            "Negotiating proof signing algorithm"
        );

        // Return the first signing algorithm that matches any of the Credential Issuer's supported signing algorithms.
        let selected = wallet_algorithms
            .find(|supported_algorithm| {
                // Since `Algorithm` does not implement `Display`, we need to use `Debug` in order to convert it to a `String`.
                let supported_algorithm_str = format!("{supported_algorithm:?}");
                credential_issuer_proof_signing_alg_values_supported
                    .contains(&AlgIdentifier::String(supported_algorithm_str))
            })
            .cloned();

        match selected {
            Some(algorithm) => {
                tracing::debug!(?algorithm, "Selected proof signing algorithm");
                Ok(algorithm)
            }
            None => Err(anyhow::anyhow!("No matching supported signing algorithms found.")),
        }
    }

    /// How the key proof for `credential_configuration` names the Wallet's key. By `kid`, unless the Credential Issuer
    /// binds credentials to none of the Wallet's subject syntax types but does bind them to a JWK
    /// (`cryptographic_binding_methods_supported` has `jwk`): then by `jwk`, the key itself.
    fn select_proof_key_reference(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> ProofKeyReference {
        let binding_methods = &credential_configuration.cryptographic_binding_methods_supported;
        let binds_to_a_supported_syntax_type = binding_methods
            .iter()
            .filter_map(|binding_method| SubjectSyntaxType::from_str(binding_method).ok())
            .any(|binding_method| {
                self.supported_subject_syntax_types
                    .iter()
                    .any(|supported| is_bound_to(supported, &binding_method))
            });

        if !binds_to_a_supported_syntax_type && binding_methods.iter().any(|binding_method| binding_method == "jwk") {
            ProofKeyReference::Jwk
        } else {
            ProofKeyReference::Kid
        }
    }

    #[tracing::instrument(level = "debug", err, skip(self, credential_configuration))]
    fn select_subject_syntax_type(
        &self,
        credential_configuration: &CredentialConfigurationsSupportedObject,
    ) -> Result<SubjectSyntaxType> {
        if !credential_configuration
            .cryptographic_binding_methods_supported
            .is_empty()
            && credential_configuration.proof_types_supported.is_empty()
        {
            return Err(anyhow::anyhow!(
                "Proof types supported must be defined if cryptographic binding methods are defined in the credential configuration."
            ));
        }

        let credential_issuer_cryptographic_binding_methods_supported: Vec<SubjectSyntaxType> =
            credential_configuration
                .cryptographic_binding_methods_supported
                .iter()
                .filter_map(|binding_method| SubjectSyntaxType::from_str(binding_method).ok())
                .collect();

        tracing::debug!(
            wallet_syntax_types = ?self.supported_subject_syntax_types,
            issuer_binding_methods = ?credential_issuer_cryptographic_binding_methods_supported,
            "Negotiating subject syntax type"
        );

        let binding_methods = &credential_issuer_cryptographic_binding_methods_supported;
        let selected = self
            .supported_subject_syntax_types
            .iter()
            .find(|supported_syntax_type| binding_methods.contains(supported_syntax_type))
            // Then one the issuer binds to by the name of its DID method, as `select_proof_key_reference` counts
            // it: the key proof is then signed under a method the issuer binds to.
            .or_else(|| {
                self.supported_subject_syntax_types
                    .iter()
                    .find(|supported_syntax_type| {
                        binding_methods
                            .iter()
                            .any(|binding_method| is_bound_to(supported_syntax_type, binding_method))
                    })
            })
            // If no match is found, use the first supported syntax type as a fallback.
            .or_else(|| self.supported_subject_syntax_types.first())
            .cloned();

        match selected {
            Some(syntax_type) => {
                tracing::debug!(%syntax_type, "Selected subject syntax type");
                Ok(syntax_type)
            }
            None => Err(anyhow::anyhow!("No supported subject syntax types found.")),
        }
    }

    #[tracing::instrument(level = "debug", err, skip(self))]
    pub async fn get_nonce(&self, nonce_endpoint: Url) -> Result<String> {
        tracing::debug!(%nonce_endpoint, "Requesting c_nonce from issuer");
        // The request has no content. Its length is still sent, as for any POST (RFC 9110, Section 8.6): the HTTP
        // client leaves the header out of a request without a body, and some servers then answer 411 Length Required.
        let response = self
            .client
            .post(nonce_endpoint)
            .header(CONTENT_LENGTH, HeaderValue::from_static("0"))
            .send()
            .await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from nonce endpoint: {e}"))?;
        tracing::trace!(%status, body = %text, "Nonce response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!("Nonce request failed (HTTP {status}): {text}"));
        }

        let NonceResponse { c_nonce } = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse nonce response (HTTP {status}, {} bytes): {e}",
                text.len()
            )
        })?;

        tracing::debug!("Successfully received c_nonce");
        Ok(c_nonce)
    }

    #[tracing::instrument(level = "debug", err, skip(self, token_response, nonce, credential_configuration))]
    pub async fn get_credential(
        &self,
        credential_issuer_metadata: CredentialIssuerMetadata,
        token_response: &TokenResponse,
        nonce: Option<String>,
        credential_configuration_id: String,
        credential_configuration: &CredentialConfigurationsSupportedObject,
        with_anonymous_access: bool,
    ) -> Result<CredentialResponse> {
        tracing::info!(
            endpoint = %credential_issuer_metadata.credential_endpoint,
            %credential_configuration_id,
            "Requesting credential issuance from issuer"
        );
        let key_reference = self.select_proof_key_reference(credential_configuration);
        let signing_algorithm = self.select_signing_algorithm(credential_configuration, key_reference)?;
        let subject_syntax_type = self.select_subject_syntax_type(credential_configuration)?;
        tracing::debug!(
            ?signing_algorithm,
            %subject_syntax_type,
            ?key_reference,
            "Selected proof signing algorithm, syntax type and key reference"
        );

        let mut proof_builder = Proof::builder()
            .proof_type(ProofType::Jwt)
            .algorithm(signing_algorithm)
            .key_reference(key_reference)
            .signer(self.subject.clone());

        if !with_anonymous_access {
            proof_builder = proof_builder.iss(
                self.subject
                    .identifier(&subject_syntax_type.to_string(), signing_algorithm)
                    .await?,
            );
        }

        proof_builder = proof_builder
            .aud(credential_issuer_metadata.credential_issuer)
            .iat(chrono::Utc::now().timestamp());

        if let Some(nonce) = nonce {
            proof_builder = proof_builder.nonce(nonce);
        }

        // TODO: Update ProofBuilder to produce Proofs instead of Proof.
        let single_proof_object = Some(
            proof_builder
                .subject_syntax_type(subject_syntax_type.to_string())
                .build()
                .await?,
        );

        let jwt_string = match single_proof_object {
            Some(Proof::Jwt { jwt, .. }) => jwt,
            _ => return Err(anyhow::anyhow!("No JWT found in proof object")),
        };

        let proofs = Some(Proofs {
            jwt: vec![jwt_string.clone()],
        });

        let credential_request = CredentialRequest {
            credential_identifier_or_credential_configuration_id:
                CredentialIdentifierOrCredentialConfigurationId::CredentialConfigurationId(credential_configuration_id),
            proofs,
        };

        tracing::info!("Sending credential request to issuer");
        tracing::trace!(?credential_request, "Credential request");

        // A proof with a `jwk` header has no `kid` to read.
        if key_reference == ProofKeyReference::Kid
            && let Ok((kid, alg)) = oid4vc_core::jwt::extract_header(&jwt_string)
        {
            tracing::debug!(%kid, ?alg, "Proof JWT header parameters");
        }

        let response = self
            .client
            .post(credential_issuer_metadata.credential_endpoint)
            .bearer_auth(token_response.access_token.clone())
            .json(&credential_request)
            .send()
            .await?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body from credential endpoint: {e}"))?;
        tracing::trace!(%status, body = %text, "Credential response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!("Credential issuance failed (HTTP {status}): {text}"));
        }

        tracing::debug!(%status, "Received credential response from issuer");
        let credential_response: CredentialResponse = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse credential response (HTTP {status}, {} bytes): {e}",
                text.len()
            )
        })?;
        tracing::info!("Successfully received credential response from issuer");
        Ok(credential_response)
    }

    /// Send an initial Interactive Authorization Request to the IAE endpoint (Section 6.1.1).
    ///
    /// This is similar to a Pushed Authorization Request but adds `interaction_types_supported`
    /// and returns an `InteractiveAuthorizationResponse` indicating the next step.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "debug", err, skip(self, state, authorization_details, issuer_state))]
    pub async fn send_interactive_authorization_request(
        &self,
        interactive_authorization_endpoint: Url,
        client_id: &str,
        redirect_uri: Option<Url>,
        state: Option<String>,
        authorization_details: Option<Vec<AuthorizationDetailsObject>>,
        issuer_state: Option<String>,
        interaction_types_supported: Vec<InteractionType>,
        code_challenge: Option<String>,
        code_challenge_method: Option<CodeChallengeMethod>,
    ) -> Result<InteractiveAuthorizationResponse> {
        tracing::info!(%interactive_authorization_endpoint, %client_id, "Sending interactive authorization request");
        let request = InteractiveAuthorizationRequest {
            authorization_request: AuthorizationRequest {
                response_type: "code".to_string(),
                client_id: client_id.to_string(),
                redirect_uri,
                // TODO: add support for `scope`, see: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-3.3.4
                scope: None,
                state,
                authorization_details,
                issuer_state,
                code_challenge,
                code_challenge_method,
            },
            interaction_types_supported: InteractiveAuthorizationRequest::interaction_types_to_string(
                &interaction_types_supported,
            ),
        };

        let url_encoded = to_form_urlencoded_string(&request)?;
        tracing::trace!(body = %url_encoded, "Interactive authorization request body");

        let response = self
            .client
            .post(interactive_authorization_endpoint)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(url_encoded)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            anyhow::anyhow!("Failed to read response body from interactive authorization endpoint: {e}")
        })?;
        tracing::trace!(%status, body = %text, "Interactive authorization response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Interactive authorization request failed (HTTP {status}): {text}"
            ));
        }

        let ia_response: InteractiveAuthorizationResponse = serde_json::from_str(&text).map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse interactive authorization response (HTTP {status}, {} bytes): {err}",
                text.len()
            )
        })?;
        tracing::debug!(
            auth_session_present = ia_response.auth_session.is_some(),
            openid4vp_request_present = ia_response.openid4vp_request.is_some(),
            "Received interactive authorization response"
        );
        Ok(ia_response)
    }

    /// Send a follow-up Interactive Authorization Request (Section 6.1.2).
    ///
    /// This is used after receiving a `require_interaction` response to submit the
    /// result of the interaction (e.g., an OpenID4VP presentation response).
    #[tracing::instrument(level = "debug", err, skip(self, follow_up))]
    pub async fn send_interactive_authorization_follow_up(
        &self,
        interactive_authorization_endpoint: Url,
        follow_up: InteractiveAuthorizationFollowUpRequest,
    ) -> Result<InteractiveAuthorizationResponse> {
        tracing::info!(%interactive_authorization_endpoint, "Sending interactive authorization follow-up");
        let url_encoded = to_form_urlencoded_string(&follow_up)?;
        tracing::trace!(body = %url_encoded, "Interactive authorization follow-up body");

        let response = self
            .client
            .post(interactive_authorization_endpoint)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(url_encoded)
            .send()
            .await?;
        let status = response.status();
        let text = response.text().await.map_err(|e| {
            anyhow::anyhow!("Failed to read response body from interactive authorization endpoint: {e}")
        })?;
        tracing::trace!(%status, body = %text, "Interactive authorization follow-up response body");

        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Interactive authorization follow-up failed (HTTP {status}): {text}"
            ));
        }

        let ia_response: InteractiveAuthorizationResponse = serde_json::from_str(&text).map_err(|err| {
            anyhow::anyhow!(
                "Failed to parse interactive authorization follow-up response (HTTP {status}, {} bytes): {err}",
                text.len()
            )
        })?;
        tracing::debug!(
            auth_session_present = ia_response.auth_session.is_some(),
            openid4vp_request_present = ia_response.openid4vp_request.is_some(),
            "Received interactive authorization follow-up response"
        );
        Ok(ia_response)
    }

    #[tracing::instrument(level = "debug", err, skip(self, access_token))]
    pub async fn send_notification_request(
        &self,
        notification_endpoint: Url,
        notification_id: String,
        access_token: String,
        event: NotificationEvent,
        event_description: Option<String>,
    ) -> Result<()> {
        tracing::info!(%notification_endpoint, %notification_id, ?event, "Sending notification request to issuer");
        let notification_request = NotificationRequest {
            notification_id,
            event,
            event_description,
        };
        let response = self
            .client
            .post(notification_endpoint)
            .bearer_auth(access_token)
            .json(&notification_request)
            .send()
            .await?;
        let status = response.status();

        if status == 204 || status == 200 {
            tracing::debug!(%status, "Notification request acknowledged");
            Ok(())
        } else {
            let text = response.text().await.unwrap_or_default();
            Err(anyhow!("Failed to send notification (HTTP {status}): {text}"))
        }
    }
}

/// Whether an issuer that binds credentials to `binding_method` binds them to the Wallet's `supported` syntax type. A
/// DID method is compared by its name: an issuer binding to `did:web` binds to the Wallet's `did:web:example`, and
/// the other way round.
fn is_bound_to(supported: &SubjectSyntaxType, binding_method: &SubjectSyntaxType) -> bool {
    match (supported, binding_method) {
        (SubjectSyntaxType::Did(supported), SubjectSyntaxType::Did(binding_method)) => {
            supported.method_name() == binding_method.method_name()
        }
        (supported, binding_method) => supported == binding_method,
    }
}

/// `client` with the retries every request of the wallet gets.
fn with_retries(client: reqwest::Client) -> ClientWithMiddleware {
    let retry_policy = ExponentialBackoff::builder().build_with_max_retries(2);
    ClientBuilder::new(client)
        .with(RetryTransientMiddleware::new_with_policy(retry_policy))
        .build()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::proof::KeyProofMetadata;
    use oid4vc_core::test_utils::TestSubject;
    use std::{collections::HashMap, sync::Arc};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    fn configuration_binding_to(binding_methods: &[&str]) -> CredentialConfigurationsSupportedObject {
        CredentialConfigurationsSupportedObject {
            cryptographic_binding_methods_supported: binding_methods.iter().map(ToString::to_string).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn key_proof_names_the_key_by_jwk_only_for_an_issuer_binding_to_jwk_and_no_supported_syntax_type() {
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();
        let key_reference =
            |binding_methods: &[&str]| wallet.select_proof_key_reference(&configuration_binding_to(binding_methods));

        // As before: no binding methods, one of the Wallet's, or none the Wallet knows.
        assert_eq!(key_reference(&[]), ProofKeyReference::Kid);
        assert_eq!(key_reference(&["did:test"]), ProofKeyReference::Kid);
        assert_eq!(key_reference(&["cose_key"]), ProofKeyReference::Kid);
        // An issuer that takes both gets the Wallet's own syntax type.
        assert_eq!(key_reference(&["jwk", "did:test"]), ProofKeyReference::Kid);

        assert_eq!(key_reference(&["jwk"]), ProofKeyReference::Jwk);
        assert_eq!(key_reference(&["jwk", "cose_key", "did:other"]), ProofKeyReference::Jwk);

        // A DID method matches by its name, with or without a namespace on either side.
        assert_eq!(key_reference(&["jwk", "did:test:namespace"]), ProofKeyReference::Kid);
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test:namespace"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();
        assert_eq!(
            wallet.select_proof_key_reference(&configuration_binding_to(&["jwk", "did:test"])),
            ProofKeyReference::Kid
        );
        assert_eq!(
            wallet.select_proof_key_reference(&configuration_binding_to(&["jwk", "did:other"])),
            ProofKeyReference::Jwk
        );
    }

    #[test]
    fn subject_syntax_type_is_one_the_issuer_binds_to_whenever_the_key_is_named_by_kid_for_it() {
        let wallet_with = |syntax_types: Vec<&str>| -> Wallet {
            Wallet::new(Arc::new(TestSubject::default()), syntax_types, vec![Algorithm::EdDSA]).unwrap()
        };
        let selected = |wallet: &Wallet, binding_methods: &[&str]| {
            let configuration = CredentialConfigurationsSupportedObject {
                proof_types_supported: HashMap::from_iter(vec![(
                    ProofType::Jwt,
                    KeyProofMetadata {
                        proof_signing_alg_values_supported: vec![AlgIdentifier::String("EdDSA".to_string())],
                    },
                )]),
                ..configuration_binding_to(binding_methods)
            };
            (
                wallet.select_proof_key_reference(&configuration),
                wallet.select_subject_syntax_type(&configuration).unwrap().to_string(),
            )
        };

        // The issuer binds to the Wallet's second syntax type by the name of its DID method: the proof is a `kid`
        // proof, and under that syntax type, not under the Wallet's first one.
        let wallet = wallet_with(vec!["did:other", "did:test:namespace"]);
        assert_eq!(
            selected(&wallet, &["jwk", "did:test"]),
            (ProofKeyReference::Kid, "did:test:namespace".to_string())
        );

        // An exact match goes first, whatever the order of the Wallet's syntax types.
        let wallet = wallet_with(vec!["did:test:namespace", "did:test"]);
        assert_eq!(
            selected(&wallet, &["did:test"]),
            (ProofKeyReference::Kid, "did:test".to_string())
        );

        // As before: with nothing the issuer binds to, the Wallet's first syntax type.
        let wallet = wallet_with(vec!["did:other", "did:test"]);
        assert_eq!(
            selected(&wallet, &["cose_key"]),
            (ProofKeyReference::Kid, "did:other".to_string())
        );
        assert_eq!(
            selected(&wallet, &["jwk"]),
            (ProofKeyReference::Jwk, "did:other".to_string())
        );
    }

    #[tokio::test]
    async fn nonce_request_has_a_content_length_of_zero() {
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        // A server that insists on the length of the content, as some do for every POST.
        Mock::given(method("POST"))
            .and(path("/nonce"))
            .and(header("content-length", "0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "c_nonce": "n-0S6_WzA2Mj" })))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(411))
            .with_priority(10)
            .mount(&mock_server)
            .await;

        let nonce_endpoint = format!("{}/nonce", mock_server.uri()).parse().unwrap();
        assert_eq!(wallet.get_nonce(nonce_endpoint).await.unwrap(), "n-0S6_WzA2Mj");
    }

    #[tokio::test]
    async fn requests_go_through_the_client_given_with_with_http_client() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-wallet-client", reqwest::header::HeaderValue::from_static("yes"));
        let wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap()
        .with_http_client(reqwest::Client::builder().default_headers(headers).build().unwrap());

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/nonce"))
            .and(header("x-wallet-client", "yes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "c_nonce": "n-0S6_WzA2Mj" })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let nonce_endpoint = format!("{}/nonce", mock_server.uri()).parse().unwrap();
        assert_eq!(wallet.get_nonce(nonce_endpoint).await.unwrap(), "n-0S6_WzA2Mj");
    }

    /// The `aud` of the key proof the wallet sends for an issuer whose metadata names it `credential_issuer`.
    async fn proof_audience_for(credential_issuer: &str, credential_endpoint: &str) -> serde_json::Value {
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();
        let metadata: CredentialIssuerMetadata = serde_json::from_value(serde_json::json!({
            "credential_issuer": credential_issuer,
            "credential_endpoint": credential_endpoint,
        }))
        .unwrap();
        let token_response = TokenResponse {
            access_token: "access-token".to_string(),
            token_type: "bearer".to_string(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            authorization_details: None,
        };

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/credential"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;
        let metadata = CredentialIssuerMetadata {
            credential_endpoint: format!("{}/credential", mock_server.uri()).parse().unwrap(),
            ..metadata
        };

        // The issuer's answer does not matter here, only what the wallet sent.
        let _ = wallet
            .get_credential(
                metadata,
                &token_response,
                None,
                "configuration".to_string(),
                &CredentialConfigurationsSupportedObject::default(),
                false,
            )
            .await;

        let requests = mock_server.received_requests().await.unwrap();
        let request: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        let proof = request["proofs"]["jwt"][0].as_str().unwrap();
        let claims: serde_json::Value = jsonwebtoken::dangerous::insecure_decode_claims(proof).unwrap();
        claims["aud"].clone()
    }

    #[tokio::test]
    async fn proof_audience_is_the_credential_issuer_identifier_as_the_metadata_has_it() {
        // "aud: REQUIRED (string). The value of this claim MUST be the Credential Issuer Identifier." (Appendix F.1)
        for identifier in [
            "https://credential-issuer.example.com",
            "https://credential-issuer.example.com/",
            "https://credential-issuer.example.com/tenant",
        ] {
            assert_eq!(
                proof_audience_for(identifier, "https://credential-issuer.example.com/credential").await,
                serde_json::json!(identifier)
            );
        }
    }

    #[test]
    fn select_signing_algorithm_returns_first_supported_signing_algorithm_when_no_proof_types_supported() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let signing_algorithm = wallet
            // The Credential Issuer does not supply the `proof_types_supported` parameter, so the Wallet will use its own
            // preferred signing algorithm
            .select_signing_algorithm(
                &CredentialConfigurationsSupportedObject::default(),
                ProofKeyReference::Kid,
            )
            .unwrap();

        assert_eq!(signing_algorithm, Algorithm::EdDSA);
    }

    #[test]
    fn select_signing_algorithm_returns_error_when_it_cannot_find_matching_signing_algorithm() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let error = wallet
            .select_signing_algorithm(
                &CredentialConfigurationsSupportedObject {
                    proof_types_supported: HashMap::from_iter(vec![(
                        ProofType::Jwt,
                        KeyProofMetadata {
                            // This proof signing algorithm will not match any of the Wallet's supported signing algorithms.
                            proof_signing_alg_values_supported: vec![AlgIdentifier::String("RS256".to_string())],
                        },
                    )]),
                    ..Default::default()
                },
                ProofKeyReference::Kid,
            )
            .unwrap_err()
            .to_string();

        assert_eq!(error, "No matching supported signing algorithms found.");
    }

    #[test]
    fn select_signing_algorithm_returns_matching_signing_algorithm() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let signing_algorithm = wallet
            .select_signing_algorithm(
                &CredentialConfigurationsSupportedObject {
                    proof_types_supported: HashMap::from_iter(vec![(
                        // This Proof Type is supported by the Wallet
                        ProofType::Jwt,
                        KeyProofMetadata {
                            // This proof signing algorithm will match the Wallet's supported signing algorithms.
                            proof_signing_alg_values_supported: vec![AlgIdentifier::String("EdDSA".to_string())],
                        },
                    )]),
                    ..Default::default()
                },
                ProofKeyReference::Kid,
            )
            .unwrap();

        assert_eq!(signing_algorithm, Algorithm::EdDSA);
    }

    #[test]
    fn select_signing_algorithm_for_a_jwk_proof_skips_algorithms_whose_keys_have_no_jwk_form() {
        // A Wallet that prefers an algorithm whose key cannot be sent as a `jwk`.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::RS256, Algorithm::ES256],
        )
        .unwrap();
        let taking = |algorithms: &[&str]| CredentialConfigurationsSupportedObject {
            proof_types_supported: HashMap::from_iter(vec![(
                ProofType::Jwt,
                KeyProofMetadata {
                    proof_signing_alg_values_supported: algorithms
                        .iter()
                        .map(|algorithm| AlgIdentifier::String(algorithm.to_string()))
                        .collect(),
                },
            )]),
            ..Default::default()
        };
        let select = |credential_configuration: &CredentialConfigurationsSupportedObject, key_reference| {
            wallet.select_signing_algorithm(credential_configuration, key_reference)
        };

        // A `kid` proof keeps the Wallet's order of preference.
        let both = taking(&["RS256", "ES256"]);
        assert_eq!(select(&both, ProofKeyReference::Kid).unwrap(), Algorithm::RS256);
        assert_eq!(select(&both, ProofKeyReference::Jwk).unwrap(), Algorithm::ES256);

        // Also when the Credential Issuer names no algorithms.
        let any = CredentialConfigurationsSupportedObject::default();
        assert_eq!(select(&any, ProofKeyReference::Kid).unwrap(), Algorithm::RS256);
        assert_eq!(select(&any, ProofKeyReference::Jwk).unwrap(), Algorithm::ES256);

        // An issuer taking only the other algorithm gets no `jwk` proof.
        assert!(select(&taking(&["RS256"]), ProofKeyReference::Jwk).is_err());
    }

    #[tokio::test]
    async fn wallet_successfully_retrieves_authorization_server_metadata() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-authorization-server/some/path"))
            .respond_with(ResponseTemplate::new(200).set_body_json(AuthorizationServerMetadata::default()))
            .mount(&mock_server)
            .await;

        // Assert that the Wallet can get the Authorization Server Metadata from the Credential Issuer URL with or without a trailing slash.
        let credential_issuer_url = format!("{}/some/path/", mock_server.uri()).parse().unwrap();
        assert!(
            wallet
                .get_authorization_server_metadata(credential_issuer_url)
                .await
                .is_ok()
        );

        let credential_issuer_url = format!("{}/some/path", mock_server.uri()).parse().unwrap();
        assert!(
            wallet
                .get_authorization_server_metadata(credential_issuer_url)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn wallet_successfully_retrieves_authorization_server_metadata_from_openid_configuration() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/some/path/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(AuthorizationServerMetadata::default()))
            .mount(&mock_server)
            .await;

        // Assert that the Wallet can get the Authorization Server Metadata from the Credential Issuer URL with or without a trailing slash.
        let credential_issuer_url = format!("{}/some/path/", mock_server.uri()).parse().unwrap();
        assert!(
            wallet
                .get_authorization_server_metadata(credential_issuer_url)
                .await
                .is_ok()
        );

        let credential_issuer_url = format!("{}/some/path", mock_server.uri()).parse().unwrap();
        assert!(
            wallet
                .get_authorization_server_metadata(credential_issuer_url)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn wallet_successfully_retrieves_credential_issuer_metadata() {
        // Create a new Wallet.
        let wallet: Wallet = Wallet::new(
            Arc::new(TestSubject::default()),
            vec!["did:test"],
            vec![Algorithm::EdDSA],
        )
        .unwrap();

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-credential-issuer/some/path"))
            .respond_with(ResponseTemplate::new(200).set_body_json(CredentialIssuerMetadata::default()))
            .mount(&mock_server)
            .await;

        // Assert that the Wallet can get the Credential Issuer Metadata from the Credential Issuer URL with or without a trailing slash.
        let credential_issuer_url = format!("{}/some/path/", mock_server.uri()).parse().unwrap();
        assert!(
            wallet
                .get_credential_issuer_metadata(credential_issuer_url)
                .await
                .is_ok()
        );

        let credential_issuer_url = format!("{}/some/path", mock_server.uri()).parse().unwrap();
        assert!(
            wallet
                .get_credential_issuer_metadata(credential_issuer_url)
                .await
                .is_ok()
        );
    }
}
