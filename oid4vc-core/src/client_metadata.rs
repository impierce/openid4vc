use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
use url::Url;

/// [`ClientMetadataResource`] is a request parameter used by a relying party (`siopv2::RelyingParty`) to communicate
/// its capabilities to a provider (`siopv2::Provider`).
#[skip_serializing_none]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMetadataResource<T = ()> {
    // TODO: Add all fields described in https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    ClientMetadata {
        client_name: Option<String>,
        logo_uri: Option<Url>,
        /// As described in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591.html#section-2), the client metadata can be
        /// expanded with Extensions and profiles.
        #[serde(flatten)]
        extension: T,
        #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
        other: HashMap<String, serde_json::Value>,
    },
    ClientMetadataUri(String),
}

impl<T: serde::de::DeserializeOwned> ClientMetadataResource<T> {
    /// The client metadata a `client_metadata_uri` returns: the metadata object itself, as `client_metadata` holds it
    /// inline, not wrapped in a `client_metadata` member.
    pub fn from_metadata(metadata: serde_json::Value) -> serde_json::Result<Self> {
        serde_json::from_value(serde_json::json!({ "client_metadata": metadata }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_metadata_reads_the_metadata_object_itself() {
        let resource = ClientMetadataResource::<()>::from_metadata(
            json!({ "client_name": "Verifier", "jwks_uri": "https://example.com/jwks" }),
        )
        .unwrap();
        let ClientMetadataResource::ClientMetadata { client_name, other, .. } = resource else {
            panic!("expected inline metadata");
        };
        assert_eq!(client_name.as_deref(), Some("Verifier"));
        assert_eq!(other["jwks_uri"], "https://example.com/jwks");
    }
}
