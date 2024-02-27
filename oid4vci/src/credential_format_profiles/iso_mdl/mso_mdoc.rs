use crate::credential_format;

credential_format!("mso_mdoc", MsoMdoc, {
    doctype: String,
    claims: Option<serde_json::Value>,
    // TODO: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-12.html#appendix-E.2.2-2.3.
    order: Option<Vec<String>>
});
