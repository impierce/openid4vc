use crate::credential_format_profiles::{CredentialFormatCollection, CredentialFormats, WithCredential};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Credential Response as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response.
#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct CredentialResponse<CFC = CredentialFormats<WithCredential>>
where
    CFC: CredentialFormatCollection,
{
    #[serde(flatten)]
    pub credential: CredentialResponseType<CFC>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct BatchCredentialResponse {
    pub credential_responses: Vec<CredentialResponseType>,
    pub c_nonce: Option<String>,
    pub c_nonce_expires_in: Option<u64>,
}

#[skip_serializing_none]
#[derive(Serialize, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum CredentialResponseType<CFC = CredentialFormats<WithCredential>>
where
    CFC: CredentialFormatCollection,
{
    Deferred { transaction_id: String },
    Immediate(CFC),
}
