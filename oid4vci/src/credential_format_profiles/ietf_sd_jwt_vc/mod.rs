use crate::credential_format;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

credential_format!("vc+sd-jwt", VcSdJwt, {
    vct: String,
    claims: Option<serde_json::Value>,
    order: Option<Vec<String>>
});
