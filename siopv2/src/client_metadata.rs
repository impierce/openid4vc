use getset::Getters;
use oid4vc_core::SubjectSyntaxType;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

/// [`ClientMetadata`] is a request parameter used by a [`crate::RelyingParty`] to communicate its capabilities to a [`crate::Provider`].
#[skip_serializing_none]
#[derive(Getters, Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct ClientMetadata {
    #[getset(get = "pub")]
    subject_syntax_types_supported: Option<Vec<SubjectSyntaxType>>,
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
    use crate::RequestUrl;
    use oid4vc_core::DidMethod;
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

        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &client_metadata=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Atest%22%5D%2C%0A%20%20%20%20\
                %22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%7D\
                &nonce=n-0S6_WzA2Mj\
            ",
        )
        .unwrap();

        assert_eq!(
            RequestUrl::from_str(&RequestUrl::to_string(&request_url)).unwrap(),
            request_url
        );
    }
}
