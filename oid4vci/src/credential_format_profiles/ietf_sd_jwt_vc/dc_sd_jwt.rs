use crate::credential_format;

credential_format!("dc+sd-jwt", DcSdJwt, {
    vct: String,
    claims: Option<serde_json::Value>,
    order: Option<Vec<String>>
});
