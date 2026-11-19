use nutype::nutype;
use reqwest::Url;

/// The Credential Issuer Identifier (OpenID4VCI 1.0, Section 12.2.1), kept as the string it was received as.
///
/// It is compared, and repeated to the Credential Issuer, as that string: the Credential Issuer Metadata is used only
/// when its `credential_issuer` is identical to the identifier "using a simple string comparison with no
/// normalization" (Section 12.2.4), and the `aud` of a key proof "MUST be the Credential Issuer Identifier"
/// (Appendix F.1). A `Url` cannot hold it for that: it normalizes, so `https://issuer.example` and
/// `https://issuer.example/` become the same value, written with the slash.
///
/// The string has to parse as a URL, since the location of the metadata derives from it; see [`Self::url`].
#[nutype(
    validate(predicate = is_url),
    derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, AsRef, Deref, FromStr)
)]
pub struct CredentialIssuerIdentifier(String);

fn is_url(value: &str) -> bool {
    value.parse::<Url>().is_ok()
}

impl CredentialIssuerIdentifier {
    /// The identifier as a URL, to derive the location of its metadata. Not for comparing identifiers, and not for
    /// sending one: the URL is normalized, see [`CredentialIssuerIdentifier`].
    pub fn url(&self) -> Url {
        self.parse().expect("a Credential Issuer Identifier parses as a URL")
    }
}

/// The identifier a URL is written as, which ends in a slash when the URL has no path.
impl From<Url> for CredentialIssuerIdentifier {
    fn from(url: Url) -> Self {
        Self::try_new(String::from(url)).expect("a URL written as a string parses as a URL")
    }
}

impl From<CredentialIssuerIdentifier> for String {
    fn from(identifier: CredentialIssuerIdentifier) -> Self {
        identifier.into_inner()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for CredentialIssuerIdentifier {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::schema::Type::String)
            .format(Some(utoipa::openapi::SchemaFormat::KnownFormat(
                utoipa::openapi::KnownFormat::Uri,
            )))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for CredentialIssuerIdentifier {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_string_it_was_given() {
        for identifier in [
            "https://issuer.example",
            "https://issuer.example/",
            "https://issuer.example/tenant",
        ] {
            let parsed: CredentialIssuerIdentifier = identifier.parse().unwrap();
            assert_eq!(parsed.as_ref(), identifier);
            assert_eq!(parsed.to_string(), identifier);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), serde_json::json!(identifier));
            assert_eq!(
                serde_json::from_value::<CredentialIssuerIdentifier>(serde_json::json!(identifier)).unwrap(),
                parsed
            );
        }
    }

    #[test]
    fn identifiers_differing_in_a_trailing_slash_are_not_equal() {
        let without: CredentialIssuerIdentifier = "https://issuer.example".parse().unwrap();
        let with: CredentialIssuerIdentifier = "https://issuer.example/".parse().unwrap();
        assert_ne!(without, with);
        // As URLs they are the same, which is why the identifier is not a `Url`.
        assert_eq!(without.url(), with.url());
    }

    #[test]
    fn a_string_that_is_no_url_is_refused() {
        assert!("issuer.example".parse::<CredentialIssuerIdentifier>().is_err());
        assert!(serde_json::from_value::<CredentialIssuerIdentifier>(serde_json::json!("not a url")).is_err());
        assert!(serde_json::from_value::<CredentialIssuerIdentifier>(serde_json::json!(42)).is_err());
    }

    #[test]
    fn from_a_url_it_is_the_url_as_written() {
        let url: Url = "https://issuer.example".parse().unwrap();
        assert_eq!(
            CredentialIssuerIdentifier::from(url).as_ref(),
            "https://issuer.example/"
        );
        let url: Url = "https://issuer.example/tenant".parse().unwrap();
        assert_eq!(
            CredentialIssuerIdentifier::from(url).as_ref(),
            "https://issuer.example/tenant"
        );
    }
}
