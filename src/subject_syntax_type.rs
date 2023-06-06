use serde::{de::Error, Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SubjectSyntaxType {
    #[serde(with = "serde_jwk_thumbprint")]
    JwkThumbprint,
    Did(DidMethod),
}

impl TryFrom<String> for SubjectSyntaxType {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "urn:ietf:params:oauth:jwk-thumbprint" => Ok(SubjectSyntaxType::JwkThumbprint),
            _ => Ok(SubjectSyntaxType::Did(serde_json::from_value(
                serde_json::Value::String(value),
            )?)),
        }
    }
}

pub mod serde_jwk_thumbprint {
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
            .then(|| ())
            .ok_or(Error::custom("Invalid subject syntax type"))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(transparent)]
pub struct DidMethod(
    #[serde(deserialize_with = "deserialize_did_method", serialize_with = "serialize_did_method")] pub String,
);

fn deserialize_did_method<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut did_scheme = s.splitn(3, ':');

    match (did_scheme.next(), did_scheme.next(), did_scheme.next()) {
        (Some("did"), Some(method), None) if !method.is_empty() && method.chars().all(char::is_alphanumeric) => {
            Ok(method.to_owned())
        }
        _ => Err(Error::custom("Invalid DID method")),
    }
}

fn serialize_did_method<S>(did_method: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("did:{}", did_method))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientMetadata;

    #[test]
    fn test_subject_syntax_type_serde() {
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
                SubjectSyntaxType::Did(DidMethod("example".to_string())),
                SubjectSyntaxType::JwkThumbprint,
            ])
        );

        // let client_metadata: ClientMetadata = serde_json::from_value(json).unwrap();

        // let client_metadata = ClientMetadata::default()
        //     .with_subject_syntax_types_supported(vec![SubjectSyntaxType::Did(DidMethod("example".to_string()))]);

        // assert_eq!(
        //     SubjectSyntaxType::JwkThumbprint,
        //     serde_json::from_str::<SubjectSyntaxType>(r#""urn:ietf:params:oauth:jwk-thumbprint""#).unwrap()
        // );

        // assert_eq!(
        //     SubjectSyntaxType::Did(DidMethod("example".to_string())),
        //     serde_json::from_str::<SubjectSyntaxType>(r#"did:example"#).unwrap()
        // );
    }
}
