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
            _ => Ok(SubjectSyntaxType::Did(DidMethod::from_str(s)?)),
        }
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
pub struct DidMethod(String);

impl From<did_url::DID> for DidMethod {
    fn from(did: did_url::DID) -> Self {
        DidMethod(did.method().to_owned())
    }
}

impl FromStr for DidMethod {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut did_scheme = s.splitn(3, ':');

        match (
            did_scheme.next(),
            did_scheme.next(),
            did_scheme.next(),
            did_scheme.next(),
        ) {
            (Some("did"), Some(method), _, None) if !method.is_empty() && method.chars().all(char::is_alphanumeric) => {
                Ok(DidMethod(method.to_owned()))
            }
            _ => Err(Error::custom("Invalid DID method")),
        }
    }
}

impl Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}", self.0.as_str())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::ClientMetadata;

//     #[test]
//     fn test_did_method() {
//         assert!(DidMethod::from_str("").is_err());
//         assert!(DidMethod::from_str("did").is_err());
//         assert!(DidMethod::from_str("did:").is_err());
//         assert!(DidMethod::from_str("invalid:").is_err());
//         // assert!(DidMethod::from_str("did:example:").is_err());
//         assert!(DidMethod::from_str("did:example_").is_err());
//         assert!(DidMethod::from_str("did:example").is_ok());
//     }

//     #[test]
//     fn test_subject_syntax_type_serde() {
//         let client_metadata: ClientMetadata = serde_json::from_value(serde_json::json!(
//             {
//                 "subject_syntax_types_supported": [
//                     "did:example",
//                     "urn:ietf:params:oauth:jwk-thumbprint"
//                 ]
//             }
//         ))
//         .unwrap();
//         assert_eq!(
//             client_metadata,
//             ClientMetadata::default().with_subject_syntax_types_supported(vec![
//                 SubjectSyntaxType::Did(DidMethod::from_str("did:example").unwrap()),
//                 SubjectSyntaxType::JwkThumbprint,
//             ])
//         );

//         assert_eq!(
//             SubjectSyntaxType::JwkThumbprint,
//             serde_json::from_str::<SubjectSyntaxType>(r#""urn:ietf:params:oauth:jwk-thumbprint""#).unwrap()
//         );

//         assert_eq!(
//             SubjectSyntaxType::Did(DidMethod::from_str("did:example").unwrap()),
//             serde_json::from_str::<SubjectSyntaxType>(r#""did:example""#).unwrap()
//         );
//     }
// }
