use getset::Getters;
use is_empty::IsEmpty;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Set of IANA registered claims by the Internet Engineering Task Force (IETF) in
/// [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1).
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone, IsEmpty, Getters)]
pub struct RFC7519Claims {
    #[getset(get = "pub")]
    pub iss: Option<String>,
    #[getset(get = "pub")]
    pub sub: Option<String>,
    #[getset(get = "pub")]
    pub aud: Option<String>,
    #[getset(get = "pub")]
    pub exp: Option<i64>,
    #[getset(get = "pub")]
    pub nbf: Option<i64>,
    #[getset(get = "pub")]
    pub iat: Option<i64>,
    #[getset(get = "pub")]
    pub jti: Option<String>,
}
