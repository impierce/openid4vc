use crate::authorization_details::AuthorizationDetailsObject;
use crate::authorization_request::CodeChallengeMethod;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// Interaction types supported by the Wallet as defined in Section 6.1.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionType {
    /// The Wallet supports an OpenID4VP Presentation interaction.
    #[serde(rename = "urn:openid:dcp:iae:openid4vp_presentation")]
    OpenId4VpPresentation,
    /// The Wallet supports a redirect to a web-based interaction.
    #[serde(rename = "urn:openid:dcp:iae:redirect_to_web")]
    RedirectToWeb,
    /// Custom interaction type defined by an extension.
    #[serde(untagged)]
    Custom(String),
}

/// The initial request to the Interactive Authorization Endpoint, as defined in Section 6.1.1.
///
/// Formed and sent in the same way as a PAR request (RFC 9126 Section 2.1), with the addition
/// of the `interaction_types_supported` parameter.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InteractiveAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Option<Url>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub authorization_details: Vec<AuthorizationDetailsObject>,
    pub issuer_state: Option<String>,
    // PKCE parameters
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// Comma-separated list of interaction types the Wallet supports.
    pub interaction_types_supported: String,
}

impl InteractiveAuthorizationRequest {
    /// Build the `interaction_types_supported` parameter value from a list of interaction types.
    pub fn interaction_types_to_string(types: &[InteractionType]) -> String {
        types
            .iter()
            .map(|t| match t {
                InteractionType::OpenId4VpPresentation => "urn:openid:dcp:iae:openid4vp_presentation".to_string(),
                InteractionType::RedirectToWeb => "urn:openid:dcp:iae:redirect_to_web".to_string(),
                InteractionType::Custom(s) => s.clone(),
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// A follow-up request to the Interactive Authorization Endpoint, as defined in Section 6.1.2.
///
/// Follow-up requests include the `auth_session` value received most recently from the
/// Authorization Server. Additional parameters depend on the interaction type.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InteractiveAuthorizationFollowUpRequest {
    /// The auth_session value from the most recent IAE response.
    pub auth_session: String,
    /// The OpenID4VP Authorization Response (JSON-encoded), present when responding
    /// to a `urn:openid:dcp:iae:openid4vp_presentation` interaction.
    pub openid4vp_response: Option<serde_json::Value>,
    /// The PKCE code verifier, required after a `urn:openid:dcp:iae:redirect_to_web`
    /// interaction if PKCE was used in the initial request.
    pub code_verifier: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interaction_types_to_string() {
        let types = vec![InteractionType::OpenId4VpPresentation, InteractionType::RedirectToWeb];
        let result = InteractiveAuthorizationRequest::interaction_types_to_string(&types);
        assert_eq!(
            result,
            "urn:openid:dcp:iae:openid4vp_presentation,urn:openid:dcp:iae:redirect_to_web"
        );
    }

    #[test]
    fn test_interaction_type_serde() {
        let vp = InteractionType::OpenId4VpPresentation;
        let serialized = serde_json::to_string(&vp).unwrap();
        assert_eq!(serialized, "\"urn:openid:dcp:iae:openid4vp_presentation\"");

        let deserialized: InteractionType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, vp);

        let web = InteractionType::RedirectToWeb;
        let serialized = serde_json::to_string(&web).unwrap();
        assert_eq!(serialized, "\"urn:openid:dcp:iae:redirect_to_web\"");

        let deserialized: InteractionType = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, web);
    }

    #[test]
    fn test_follow_up_request_serde() {
        let request = InteractiveAuthorizationFollowUpRequest {
            auth_session: "wxroVrBY2MCq4dDNGXACS".to_string(),
            openid4vp_response: Some(serde_json::json!({
                "vp_token": "eyJ..."
            })),
            code_verifier: None,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["auth_session"], "wxroVrBY2MCq4dDNGXACS");
        assert!(json["openid4vp_response"].is_object());
        assert!(json.get("code_verifier").is_none());
    }
}
