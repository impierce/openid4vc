use serde_with::skip_serializing_none;

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    CredentialAccepted,
    CredentialFailure,
    CredentialDeleted,
}
/// Notification Request as described here: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-notification-request
#[skip_serializing_none]
#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
pub struct NotificationRequest {
    pub notification_id: String,
    pub event: NotificationEvent,
    pub event_description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_request() {
        let json_value = serde_json::json!({
            "notification_id": "123",
            "event": "credential_accepted",
            "event_description": "Credential was accepted."

        });

        let notification_request: NotificationRequest = serde_json::from_value(json_value.clone()).unwrap();

        assert_eq!(
            notification_request,
            NotificationRequest {
                notification_id: "123".to_string(),
                event: NotificationEvent::CredentialAccepted,
                event_description: Some("Credential was accepted.".to_string())
            }
        );

        assert_eq!(serde_json::json!(notification_request), json_value);
    }
}
