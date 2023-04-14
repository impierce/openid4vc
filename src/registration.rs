use getset::Getters;
use serde::{de::Deserializer, ser::Serializer, Deserialize, Serialize};
use serde_json::{Map, Value};

/// [`Registration`] is a request parameter used by a [`crate::RelyingParty`] to communicate its capabilities to a [`crate::Provider`].
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

/// Custom serialization for [`Registration`]. This is necessary because `serde_urlencoded` does not support serializing non-primitive types.
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
        serializer.serialize_str(&serde_json::to_string(&map).map_err(serde::ser::Error::custom)?)
    }
}

macro_rules! deserialize_array_field {
    ($map:expr, $field:literal) => {
        $map.get($field)
            .and_then(Value::as_array)
            .map(|v| v.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect())
    };
}

/// Custom deserialization for [`Registration`]. This is necessary because `serde_urlencoded` does not support deserializing non-primitive types.
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
