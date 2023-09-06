use crate::SubjectSyntaxType;
use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// [`ClientMetadata`] is a request parameter used by a [`crate::RelyingParty`] to communicate its capabilities to a [`crate::Provider`].
#[skip_serializing_none]
#[derive(Getters, Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct ClientMetadata {
    // TODO: Move to siopv2 crate.
    #[getset(get = "pub")]
    subject_syntax_types_supported: Option<Vec<SubjectSyntaxType>>,
    // TODO: Move to siopv2 crate.
    #[getset(get = "pub")]
    id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[getset(get = "pub")]
    client_name: Option<String>,
    #[getset(get = "pub")]
    logo_uri: Option<Url>,
}

impl ClientMetadata {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_subject_syntax_types_supported(
        mut self,
        subject_syntax_types_supported: Vec<SubjectSyntaxType>,
    ) -> Self {
        self.subject_syntax_types_supported = Some(subject_syntax_types_supported);
        self
    }

    pub fn with_id_token_signing_alg_values_supported(
        mut self,
        id_token_signing_alg_values_supported: Vec<String>,
    ) -> Self {
        self.id_token_signing_alg_values_supported = Some(id_token_signing_alg_values_supported);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DidMethod;
    use std::str::FromStr;

    #[test]
    fn test_client_metadata() {
        let client_metadata: ClientMetadata = serde_json::from_value(serde_json::json!(
            {
                "subject_syntax_types_supported": [
                    "did:example",
                    "urn:ietf:params:oauth:jwk-thumbprint"
                ]
            }
        ))
        .unwrap();
        assert_eq!(
            client_metadata,
            ClientMetadata::default().with_subject_syntax_types_supported(vec![
                SubjectSyntaxType::Did(DidMethod::from_str("did:example").unwrap()),
                SubjectSyntaxType::JwkThumbprint,
            ])
        );
    }
}
