use getset::Getters;
use serde::{Deserialize, Serialize};

/// [`Registration`] is a request parameter used by a [`crate::RelyingParty`] to communicate its capabilities to a [`crate::Provider`].
#[derive(Getters, Debug, PartialEq, Clone, Default, Deserialize, Serialize)]
pub struct Registration {
    #[getset(get = "pub")]
    subject_syntax_types_supported: Option<Vec<String>>,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

impl Registration {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_subject_syntax_types_supported(mut self, subject_syntax_types_supported: Vec<String>) -> Self {
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
    use crate::RequestUrl;
    use std::str::FromStr;

    #[test]
    fn test_registration() {
        let request_url = RequestUrl::from_str(
            "\
            siopv2://idtoken?\
                scope=openid\
                &response_type=id_token\
                &client_id=did%3Aexample%3AEiDrihTRe0GMdc3K16kgJB3Xbl9Hb8oqVHjzm6ufHcYDGA\
                &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb\
                &response_mode=post\
                &registration=%7B%22subject_syntax_types_supported%22%3A\
                %5B%22did%3Amock%22%5D%2C%0A%20%20%20%20\
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
