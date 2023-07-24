use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use crate::serialize_unit_struct;

#[derive(Debug, PartialEq)]
pub struct PreAuthorizedCode;
serialize_unit_struct!("pre_authorized_code", PreAuthorizedCode);

#[derive(Debug, PartialEq)]
pub struct AuthorizationCode;
serialize_unit_struct!("authorization_code", AuthorizationCode);

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum TokenRequest {
    AuthorizationCode {
        grant_type: AuthorizationCode,
        code: String,
        code_verifier: Option<String>,
        redirect_uri: Option<String>,
    },
    #[serde(rename = "authorization_code")]
    PreAuthorizedCode {
        grant_type: PreAuthorizedCode,
        #[serde(rename = "pre-authorized_code")]
        pre_authorized_code: String,
        user_pin: Option<String>,
    },
}
