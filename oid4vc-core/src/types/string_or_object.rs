use crate::JsonObject;
use serde::{Deserialize, Serialize};

/// Simple enum that can be used to represent either a string or a JSON object.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum StringOrObject {
    String(String),
    Object(JsonObject),
}

impl StringOrObject {
    pub fn as_str(&self) -> Option<&str> {
        if let StringOrObject::String(string) = self {
            Some(string)
        } else {
            None
        }
    }

    pub fn as_object(&self) -> Option<&JsonObject> {
        if let StringOrObject::Object(object) = self {
            Some(object)
        } else {
            None
        }
    }
}

impl From<String> for StringOrObject {
    fn from(string: String) -> Self {
        Self::String(string)
    }
}

impl From<&str> for StringOrObject {
    fn from(string: &str) -> Self {
        Self::String(string.to_string())
    }
}

impl From<JsonObject> for StringOrObject {
    fn from(object: JsonObject) -> Self {
        Self::Object(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip_string() {
        let original = StringOrObject::String("hello".to_string());
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: StringOrObject = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_roundtrip_object() {
        let original = StringOrObject::Object(JsonObject::from_iter(vec![(
            "key".to_string(),
            serde_json::json!("value"),
        )]));
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: StringOrObject = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }
}
