use crate::credential_format;

credential_format!("mso_doc", MsoDoc, {
    doctype: String,
    claims: Option<serde_json::Map<String, serde_json::Value>>,
    // TODO: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.2.2-2.3
    order: Option<Vec<String>>
});
