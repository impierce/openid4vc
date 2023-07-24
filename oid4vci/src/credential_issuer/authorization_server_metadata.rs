use derivative::{self, Derivative};
use reqwest::Url;
use serde::{Deserialize, Serialize};

// Authorization Server Metadata as described here: https://www.rfc-editor.org/rfc/rfc8414.html#section-2
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize, Derivative)]
#[derivative(Default)]
pub struct AuthorizationServerMetadata {
    // TODO: Temporary solution
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub issuer: Url,
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub authorization_endpoint: Url,
    #[derivative(Default(value = "Url::parse(\"https://example.com\").unwrap()"))]
    pub token_endpoint: Url,
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
    // Additional authorization server metadata parameters MAY also be used.
}