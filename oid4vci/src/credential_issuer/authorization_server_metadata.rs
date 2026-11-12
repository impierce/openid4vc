use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Authorization Server Metadata as defined by [RFC 8414, Section 2].
///
/// [RFC 8414, Section 2]: https://www.rfc-editor.org/rfc/rfc8414.html#section-2
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AuthorizationServerMetadata {
    pub issuer: Url,
    pub authorization_endpoint: Option<Url>,
    pub token_endpoint: Option<Url>,
    pub jwks_uri: Option<Url>,
    pub registration_endpoint: Option<Url>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Option<Vec<String>>,
    pub response_modes_supported: Option<Vec<String>>,
    pub grant_types_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub service_documentation: Option<Url>,
    pub ui_locales_supported: Option<Vec<String>>,
    pub op_policy_uri: Option<Url>,
    pub op_tos_uri: Option<Url>,
    pub revocation_endpoint: Option<Url>,
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub introspection_endpoint: Option<Url>,
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: Option<bool>,
    // Pushed Authorization Requests
    pub pushed_authorization_request_endpoint: Option<Url>,
    #[serde(default)]
    pub require_pushed_authorization_requests: Option<bool>,
    // Interactive Authorization Endpoint (Section 6, OID4VCI 1.1)
    pub interactive_authorization_endpoint: Option<Url>,
    #[serde(default)]
    pub require_interactive_authorization_request: Option<bool>,
    // Additional authorization server metadata parameters MAY also be used.
}

// TODO: Temporary solution: `issuer` has no meaningful default.
impl Default for AuthorizationServerMetadata {
    fn default() -> Self {
        Self {
            issuer: Url::parse("https://example.com").unwrap(),
            authorization_endpoint: Default::default(),
            token_endpoint: Default::default(),
            jwks_uri: Default::default(),
            registration_endpoint: Default::default(),
            scopes_supported: Default::default(),
            response_types_supported: Default::default(),
            response_modes_supported: Default::default(),
            grant_types_supported: Default::default(),
            token_endpoint_auth_methods_supported: Default::default(),
            token_endpoint_auth_signing_alg_values_supported: Default::default(),
            service_documentation: Default::default(),
            ui_locales_supported: Default::default(),
            op_policy_uri: Default::default(),
            op_tos_uri: Default::default(),
            revocation_endpoint: Default::default(),
            revocation_endpoint_auth_methods_supported: Default::default(),
            revocation_endpoint_auth_signing_alg_values_supported: Default::default(),
            introspection_endpoint: Default::default(),
            introspection_endpoint_auth_methods_supported: Default::default(),
            introspection_endpoint_auth_signing_alg_values_supported: Default::default(),
            code_challenge_methods_supported: Default::default(),
            pre_authorized_grant_anonymous_access_supported: Default::default(),
            pushed_authorization_request_endpoint: Default::default(),
            require_pushed_authorization_requests: Default::default(),
            interactive_authorization_endpoint: Default::default(),
            require_interactive_authorization_request: Default::default(),
        }
    }
}
