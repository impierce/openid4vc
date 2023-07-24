use serde::{Deserialize, Serialize};

pub trait Format: std::fmt::Debug + Serialize + Eq + PartialEq {
    type Parameters: std::fmt::Debug + Serialize + for<'de> Deserialize<'de> + Eq + PartialEq + Clone;
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CredentialFormat<F>
where
    F: Format,
{
    pub format: F,
    #[serde(flatten)]
    pub parameters: F::Parameters,
}
