use serde::Serialize;
use serde_json::json;
use serde_urlencoded;

pub fn to_form_urlencoded_string<T: Serialize>(value: &T) -> anyhow::Result<String> {
    let map: serde_json::Map<String, serde_json::Value> = json!(value)
        .as_object()
        .ok_or(anyhow::anyhow!(
            "Failed to convert value to JSON object for URL encoding"
        ))?
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
