use crate::{CredentialFormat, Format, ProofType};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[skip_serializing_none]
#[derive(Serialize, Debug, Clone)]
pub struct CredentialsSupportedObject<F>
where
    F: Format,
{
    id: Option<String>,
    #[serde(flatten)]
    credential_format: CredentialFormat<F>,
    scope: Option<String>,
    cryptographic_binding_methods_supported: Option<Vec<String>>,
    cryptographic_suites_supported: Option<Vec<String>>,
    proof_types_supported: Option<Vec<ProofType>>,
    display: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialsSupportedJson(pub serde_json::Value);

impl<F: Format> From<CredentialsSupportedObject<F>> for CredentialsSupportedJson {
    fn from(value: CredentialsSupportedObject<F>) -> Self {
        CredentialsSupportedJson(serde_json::to_value(value).unwrap())
    }
}

impl<'de, F: Format + DeserializeOwned> TryInto<CredentialFormat<F>> for CredentialsSupportedJson
where
    CredentialFormat<F>: Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_into(self) -> Result<CredentialFormat<F>, Self::Error> {
        serde_json::from_value(self.0)
    }
}
