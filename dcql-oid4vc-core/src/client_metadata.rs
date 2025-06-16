use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;
use url::Url;

/// [`ClientMetadata`] is a request parameter used by a [`crate::RelyingParty`] to communicate its capabilities to a
/// [`crate::Provider`].
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
