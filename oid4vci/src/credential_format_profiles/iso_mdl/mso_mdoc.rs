use crate::credential_format;

credential_format!("mso_mdoc", MsoMdoc, {
    doctype: String,
    claims: Option<JsonValue>,
    // TODO: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#appendix-E.2.2-2.3
    order: Option<Vec<String>>
});
