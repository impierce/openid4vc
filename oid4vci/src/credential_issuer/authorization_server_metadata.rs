use derivative::{self, Derivative};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// Authorization Server Metadata as described here: https://www.rfc-editor.org/rfc/rfc8414.html#section-2
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative, PartialEq)]
#[derivative(Default)]
pub struct AuthorizationServerMetadata {
    // TODO: Temporary solution
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
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
    // Additional authorization server metadata parameters MAY also be used.
}
