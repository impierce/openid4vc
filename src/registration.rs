use getset::Getters;
use serde::{
    de::Deserializer,
    ser::{Error, Serializer},
    Deserialize, Serialize,
};
use serde_json::{Map, Value};

#[derive(Getters, Debug, PartialEq, Clone)]
pub struct Registration {
    #[getset(get = "pub")]
    pub subject_syntax_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

macro_rules! insert_optional_field {
    ($map:expr, $field_name:literal, $field_value:expr) => {
        if let Some(value) = &$field_value {
            $map.insert(
                $field_name.to_string(),
                Value::Array(value.iter().map(|v| Value::String(v.clone())).collect()),
            );
        }
    };
}

impl Serialize for Registration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = Map::new();
        insert_optional_field!(
            map,
            "subject_syntax_types_supported",
            self.subject_syntax_types_supported
        );
        insert_optional_field!(
            map,
            "id_token_signing_alg_values_supported",
            self.id_token_signing_alg_values_supported
        );
        serializer.serialize_str(&serde_json::to_string(&map).map_err(S::Error::custom)?)
    }
}

macro_rules! deserialize_array_field {
    ($map:expr, $field:literal) => {
        $map.get($field)
            .and_then(Value::as_array)
            .map(|v| v.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect())
    };
}

impl<'de> Deserialize<'de> for Registration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map = serde_json::from_str::<Map<String, Value>>(&String::deserialize(deserializer)?).unwrap();

        Ok(Registration {
            subject_syntax_types_supported: deserialize_array_field!(map, "subject_syntax_types_supported"),
            id_token_signing_alg_values_supported: deserialize_array_field!(
                map,
                "id_token_signing_alg_values_supported"
            ),
        })
    }
}
