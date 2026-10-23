use getset::Getters;
use is_empty::IsEmpty;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr, PickFirst};

/// Set of IANA registered claims by the Internet Engineering Task Force (IETF) in
/// [RFC 7519](https://tools.ietf.org/html/rfc7519#section-4.1).
///
/// The NumericDate claims (`exp`, `nbf`, `iat`) serialize as JSON numbers and also accept a string of
/// digits: the URL form of an Authorization Request carries every parameter as a string.
#[serde_as]
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
    #[serde_as(as = "Option<PickFirst<(_, DisplayFromStr)>>")]
    pub exp: Option<i64>,
    #[getset(get = "pub")]
    #[serde_as(as = "Option<PickFirst<(_, DisplayFromStr)>>")]
    pub nbf: Option<i64>,
    #[getset(get = "pub")]
    #[serde_as(as = "Option<PickFirst<(_, DisplayFromStr)>>")]
    pub iat: Option<i64>,
    #[getset(get = "pub")]
    pub jti: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_numeric_dates_serialize_as_numbers_and_accept_strings() {
        let claims = RFC7519Claims {
            exp: Some(1700000000),
            ..Default::default()
        };
        assert_eq!(serde_json::to_value(&claims).unwrap(), json!({"exp": 1700000000}));
        assert_eq!(
            serde_json::from_value::<RFC7519Claims>(json!({"exp": "1700000000"})).unwrap(),
            claims
        );
        assert!(serde_json::from_value::<RFC7519Claims>(json!({"exp": "soon"})).is_err());
    }
}
