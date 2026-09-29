use crate::credential_format;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

credential_format!("vc+sd-jwt", VcSdJwt, {
    credential_definition: CredentialDefinition
});

/// Credential definition for the `vc+sd-jwt` format.
#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "utoipa", schema(as = VcSdJwtCredentialDefinition))]
pub struct CredentialDefinition {
    #[serde(rename = "type")]
    pub type_: Vec<String>,
}
