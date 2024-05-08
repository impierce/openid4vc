use serde::{de::Error, Deserialize, Deserializer, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt::Display, str::FromStr};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubjectSyntaxType {
    #[serde(with = "serde_unit_variant")]
    JwkThumbprint,
    Did(DidMethod),
}

impl FromStr for SubjectSyntaxType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "urn:ietf:params:oauth:jwk-thumbprint" => Ok(SubjectSyntaxType::JwkThumbprint),
            _ => Ok(SubjectSyntaxType::Did(
                DidMethod::from_str_with_namespace(s).or_else(|_| DidMethod::from_str(s))?,
            )),
        }
    }
}

impl Display for SubjectSyntaxType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubjectSyntaxType::JwkThumbprint => write!(f, "urn:ietf:params:oauth:jwk-thumbprint"),
            SubjectSyntaxType::Did(did_method) => write!(f, "{}", did_method),
        }
    }
}

impl TryFrom<&str> for SubjectSyntaxType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        SubjectSyntaxType::from_str(value)
    }
}

impl From<DidMethod> for SubjectSyntaxType {
    fn from(did_method: DidMethod) -> Self {
        SubjectSyntaxType::Did(did_method)
    }
}

pub mod serde_unit_variant {
    use super::*;

    static JWK_THUMBPRINT: &str = "urn:ietf:params:oauth:jwk-thumbprint";

    pub fn serialize<S>(serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(JWK_THUMBPRINT)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        (s == JWK_THUMBPRINT)
            .then_some(())
            .ok_or(Error::custom("Invalid subject syntax type"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, DeserializeFromStr, SerializeDisplay)]
pub struct DidMethod {
    method_name: String,
    namespace: Option<String>,
}

impl DidMethod {
    pub fn from_str_with_namespace(s: &str) -> Result<Self, serde_json::Error> {
        let mut did_scheme = s.splitn(4, ':');

        match (
            did_scheme.next(),
            did_scheme.next(),
            did_scheme.next(),
            did_scheme.next(),
        ) {
            (Some("did"), Some(method), Some(namespace), None)
                if !method.is_empty() && !namespace.is_empty() && method.chars().all(char::is_alphanumeric) =>
            {
                Ok(DidMethod {
                    method_name: method.to_owned(),
                    namespace: Some(namespace.to_owned()),
                })
            }
            _ => Err(Error::custom("Invalid DID method")),
        }
    }
}

impl From<did_url::DID> for DidMethod {
    fn from(did: did_url::DID) -> Self {
        DidMethod {
            method_name: did.method().to_owned(),
            namespace: None,
        }
    }
}

impl FromStr for DidMethod {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut did_scheme = s.splitn(3, ':');

        match (did_scheme.next(), did_scheme.next(), did_scheme.next()) {
            (Some("did"), Some(method), None) if !method.is_empty() && method.chars().all(char::is_alphanumeric) => {
                Ok(DidMethod {
                    method_name: method.to_owned(),
                    namespace: None,
                })
            }
            _ => Err(Error::custom("Invalid DID method")),
        }
    }
}

impl Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}", self.method_name.as_str())?;
        if let Some(namespace) = &self.namespace {
            write!(f, ":{}", namespace.as_str())?;
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_method() {
        assert!(DidMethod::from_str("").is_err());
        assert!(DidMethod::from_str("did").is_err());
        assert!(DidMethod::from_str("did:").is_err());
        assert!(DidMethod::from_str("invalid:").is_err());
        assert!(DidMethod::from_str("did:example_").is_err());
        assert!(DidMethod::from_str("did:example").is_ok());
        assert!(DidMethod::from_str("did:example:").is_err());

        assert_eq!(DidMethod::from_str("did:example").unwrap().to_string(), "did:example");
        assert_eq!(
            DidMethod::from_str_with_namespace("did:example:namespace")
                .unwrap()
                .to_string(),
            "did:example:namespace"
        );
        assert!(DidMethod::from_str_with_namespace("did:example:namespace:").is_err());
        assert!(DidMethod::from_str_with_namespace("did:example:namespace:123").is_err());
    }

    #[test]
    fn test_subject_syntax_type_serde() {
        assert_eq!(
            SubjectSyntaxType::JwkThumbprint,
            serde_json::from_str::<SubjectSyntaxType>(r#""urn:ietf:params:oauth:jwk-thumbprint""#).unwrap()
        );

        assert_eq!(
            SubjectSyntaxType::Did(DidMethod::from_str("did:example").unwrap()),
            serde_json::from_str::<SubjectSyntaxType>(r#""did:example""#).unwrap()
        );
    }
}
