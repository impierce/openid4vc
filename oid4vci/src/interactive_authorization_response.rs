use crate::interactive_authorization_request::InteractionType;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// The response status from the Interactive Authorization Endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractiveAuthorizationStatus {
    /// The authorization process requires further user interaction.
    RequireInteraction,
    /// The authorization process completed successfully.
    Ok,
}

/// Response from the Interactive Authorization Endpoint, as defined in Section 6.2.
///
/// The response indicates either that user interaction is required, that the authorization
/// was completed successfully (with an authorization code), or an error.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveAuthorizationResponse {
    /// Whether an additional interaction is required or the authorization has been completed.
    pub status: InteractiveAuthorizationStatus,

    // --- Fields for `status: "ok"` (Authorization Code Response, Section 6.2.2) ---
    /// The authorization code, present when `status` is `ok`.
    pub code: Option<String>,

    // --- Fields for `status: "require_interaction"` (Section 6.2.1) ---
    /// The interaction type required by the Authorization Server.
    #[serde(rename = "type")]
    pub interaction_type: Option<InteractionType>,

    /// A value that allows the Authorization Server to associate subsequent requests
    /// with the ongoing authorization request sequence. Must be included in follow-up requests.
    pub auth_session: Option<String>,

    // --- Fields specific to `urn:openid:dcp:iae:openid4vp_presentation` (Section 6.2.1.1) ---
    /// An OpenID4VP Authorization Request for the Wallet to process.
    /// May contain either a plain request object or a signed request (`{"request": "eyJ..."}`).
    pub openid4vp_request: Option<serde_json::Value>,

    // --- Fields specific to `urn:openid:dcp:iae:redirect_to_web` (Section 6.2.1.2) ---
    /// A request_uri for building an Authorization Request via browser redirect.
    pub request_uri: Option<String>,

    /// The lifetime of the `request_uri` in seconds.
    pub expires_in: Option<i64>,
}

impl InteractiveAuthorizationResponse {
    /// Returns true if the response indicates that the authorization is complete.
    pub fn is_complete(&self) -> bool {
        self.status == InteractiveAuthorizationStatus::Ok
    }

    /// Returns the authorization code if the response is complete.
    pub fn authorization_code(&self) -> Option<&str> {
        if self.is_complete() {
            self.code.as_deref()
        } else {
            None
        }
    }
}

/// Error response from the Interactive Authorization Endpoint, as defined in Section 6.2.3.
///
/// In addition to standard PAR error processing rules (RFC 9126, Section 2.3), this
/// specification adds the `missing_interaction_type` error code.
#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveAuthorizationErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_require_presentation_response() {
        // Non-normative example from Section 6.2.1.1
        let json = serde_json::json!({
            "status": "require_interaction",
            "type": "urn:openid:dcp:iae:openid4vp_presentation",
            "auth_session": "wxroVrBY2MCq4dDNGXACS",
            "openid4vp_request": {
                "response_type": "vp_token",
                "response_mode": "iae_post",
                "dcql_query": {
                    "credentials": [{
                        "id": "some_identity_credential",
                        "format": "dc+sd-jwt",
                        "meta": {
                            "vct_values": ["https://credentials.example.com/identity_credential"]
                        },
                        "claims": [
                            {"path": ["last_name"]},
                            {"path": ["first_name"]}
                        ]
                    }]
                },
                "nonce": "n-0S6_WzA2Mj"
            }
        });

        let response: InteractiveAuthorizationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.status, InteractiveAuthorizationStatus::RequireInteraction);
        assert_eq!(response.interaction_type, Some(InteractionType::OpenId4VpPresentation));
        assert_eq!(response.auth_session.as_deref(), Some("wxroVrBY2MCq4dDNGXACS"));
        assert!(response.openid4vp_request.is_some());
        assert!(!response.is_complete());
    }

    #[test]
    fn test_deserialize_redirect_to_web_response() {
        // Non-normative example from Section 6.2.1.2
        let json = serde_json::json!({
            "status": "require_interaction",
            "type": "urn:openid:dcp:iae:redirect_to_web",
            "request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
            "expires_in": 60
        });

        let response: InteractiveAuthorizationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.status, InteractiveAuthorizationStatus::RequireInteraction);
        assert_eq!(response.interaction_type, Some(InteractionType::RedirectToWeb));
        assert_eq!(
            response.request_uri.as_deref(),
            Some("urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c")
        );
        assert_eq!(response.expires_in, Some(60));
        assert!(!response.is_complete());
    }

    #[test]
    fn test_deserialize_authorization_code_response() {
        // Non-normative example from Section 6.2.2
        let json = serde_json::json!({
            "code": "uY29tL2F1dGhlbnRpY",
            "status": "ok"
        });

        let response: InteractiveAuthorizationResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.status, InteractiveAuthorizationStatus::Ok);
        assert_eq!(response.authorization_code(), Some("uY29tL2F1dGhlbnRpY"));
        assert!(response.is_complete());
    }

    #[test]
    fn test_deserialize_error_response() {
        let json = serde_json::json!({
            "error": "missing_interaction_type",
            "error_description": "interaction_types_supported in the request is missing the required interaction type 'urn:openid:dcp:iae:openid4vp_presentation'"
        });

        let response: InteractiveAuthorizationErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(response.error, "missing_interaction_type");
        assert!(response.error_description.is_some());
    }

    #[test]
    fn test_serialize_authorization_code_response() {
        let response = InteractiveAuthorizationResponse {
            status: InteractiveAuthorizationStatus::Ok,
            code: Some("uY29tL2F1dGhlbnRpY".to_string()),
            interaction_type: None,
            auth_session: None,
            openid4vp_request: None,
            request_uri: None,
            expires_in: None,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["code"], "uY29tL2F1dGhlbnRpY");
        // None fields should be absent due to skip_serializing_none
        assert!(json.get("type").is_none());
        assert!(json.get("auth_session").is_none());
    }
}
