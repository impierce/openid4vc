use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use serde_urlencoded;
use std::collections::HashMap;

/// Serializes a value to a `x-www-form-urlencoded` string.
///
/// This function first converts the value to a JSON object. It then iterates over the key-value pairs.
/// If a value is a JSON object or array, it is serialized into a JSON string. All other JSON primitive
/// values (strings, numbers, booleans, null) are kept as-is. The resulting map is then URL-encoded.
///
/// # Arguments
///
/// * `value` - A reference to any type that implements `Serialize`. Must serialize to a JSON object.
///
/// # Returns
///
/// Returns `Ok(String)` with the URL-encoded form data, or `Err(anyhow::Error)` on failure.
///
/// # Errors
///
/// Returns an error if:
/// - The input doesn't serialize to a JSON object (e.g., primitives or arrays at top level)
/// - JSON serialization of nested structures fails
/// - URL encoding fails
///
/// # Example
///
/// ```
/// use serde::Serialize;
/// use oid4vc_core::utils::form_urlencoded::to_form_urlencoded_string;
///
/// #[derive(Serialize)]
/// struct Data {
///     name: String,
///     items: Vec<i32>,
///     details: Detail,
/// }
///
/// #[derive(Serialize)]
/// struct Detail {
///     key: String,
/// }
///
/// let data = Data {
///     name: "test".to_string(),
///     items: vec![1, 2, 3],
///     details: Detail { key: "value".to_string() },
/// };
///
/// let encoded = to_form_urlencoded_string(&data).unwrap();
/// // Nested objects and arrays are JSON-stringified and URL-encoded:
/// // details={"key":"value"} becomes details=%7B%22key%22%3A%22value%22%7D
/// // items=[1,2,3] becomes items=%5B1%2C2%2C3%5D
///
/// assert!(encoded.contains("name=test"));
/// assert!(encoded.contains("items=%5B1%2C2%2C3%5D"));
/// assert!(encoded.contains("details=%7B%22key%22%3A%22value%22%7D"));
/// ```
pub fn to_form_urlencoded_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let map: serde_json::Map<String, serde_json::Value> = json!(value)
        .as_object()
        .ok_or(anyhow::anyhow!("Expected a JSON object for serialization"))?
        .iter()
        .filter_map(|(k, v)| match v {
            serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                // If nested object or array, stringify it.
                Some((k.to_owned(), serde_json::Value::String(serde_json::to_string(v).ok()?)))
            }
            // For all other primitive types clone them directly.
            _ => Some((k.to_owned(), v.to_owned())),
        })
        .collect();

    let encoded = serde_urlencoded::to_string(map).map_err(|e| anyhow::anyhow!("Failed to URL-encode map: {}", e))?;
    Ok(encoded)
}

/// Deserializes a `x-www-form-urlencoded` string into a value.  
///  
/// This function is the inverse of `to_form_urlencoded_string`. It first decodes the  
/// URL-encoded string into a map of string keys and string values. It then attempts to  
/// parse each value as a JSON string. If parsing succeeds, the JSON value is used.  
/// If it fails (e.g., the value is a simple string like "test"), it's treated as a  
/// plain JSON string. The resulting JSON object is then deserialized into the target type.  
///  
/// # Arguments  
///  
/// * `encoded` - A `x-www-form-urlencoded` string.  
///  
/// # Returns  
///  
/// Returns `Ok(T)` with the deserialized value, or `Err(anyhow::Error)` on failure.  
///  
/// # Errors  
///  
/// Returns an error if:  
/// - The input is not valid `x-www-form-urlencoded` data.  
/// - The resulting JSON object cannot be deserialized into the target type `T`.  
///  
/// # Example  
///  
/// ```  
/// use serde::Deserialize;  
/// use oid4vc_core::utils::form_urlencoded::from_form_urlencoded_string;  
///  
/// #[derive(Deserialize, Debug, PartialEq)]  
/// struct Data {  
///     name: String,  
///     items: Vec<i32>,  
///     details: Detail,  
/// }  
///  
/// #[derive(Deserialize, Debug, PartialEq)]  
/// struct Detail {  
///     key: String,  
/// }  
///  
/// let encoded_string = "name=test&items=%5B1%2C2%2C3%5D&details=%7B%22key%22%3A%22value%22%7D";  
///  
/// let decoded: Data = from_form_urlencoded_string(encoded_string).unwrap();  
///  
/// let expected = Data {  
///     name: "test".to_string(),  
///     items: vec![1, 2, 3],  
///     details: Detail { key: "value".to_string() },  
/// };  
///  
/// assert_eq!(decoded, expected);  
/// ```
pub fn from_form_urlencoded_string<T: DeserializeOwned>(encoded: &str) -> anyhow::Result<T> {
    let string_map: HashMap<String, String> =
        serde_urlencoded::from_str(encoded).map_err(|e| anyhow::anyhow!("Failed to decodde: {}", e))?;

    // Converts the string map to a JSON map, parsing the stringified JSON values.
    let json_map: serde_json::Map<String, serde_json::Value> = string_map
        .into_iter()
        .map(|(k, v)| {
            let json_value = serde_json::from_str(&v).unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
            (k, json_value)
        })
        .collect();

    // Converts the JSON map to the wanted type.
    let value = serde_json::Value::Object(json_map);
    serde_json::from_value(value).map_err(|e| anyhow::anyhow!("Failed to deserialize into target type: {}", e))
}
