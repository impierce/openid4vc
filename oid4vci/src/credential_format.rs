use serde::{Deserialize, Serialize};

pub trait Format: std::fmt::Debug + Serialize {
    type Parameters: std::fmt::Debug + Serialize + for<'de> Deserialize<'de> + Clone;
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialFormat<F>
where
    F: Format,
{
    pub format: F,
    #[serde(flatten)]
    pub parameters: F::Parameters,
}
