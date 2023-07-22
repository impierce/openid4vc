use crate::credential_format;

credential_format!("mso_doc", MsoDoc, {
    doctype: String,
    claims: serde_json::Value
});
