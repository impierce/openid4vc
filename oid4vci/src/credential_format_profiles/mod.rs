pub mod iso_mdl;
pub mod w3c_verifiable_credentials;

use serde::{Deserialize, Serialize};

#[macro_export]
macro_rules! credential_format {
    ($format:literal, $name:ty, {$($field_name:ident: $field_type:ty),*}) => {
        paste::paste! {
            #[derive(Debug, Clone, Eq, PartialEq)]
            pub struct $name;
            impl $crate::credential_format_profiles::Format for $name {
                type Parameters = [< $name Parameters >];
            }

            #[serde_with::skip_serializing_none]
            #[derive(Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq, Clone)]
            pub struct [< $name Parameters >] {
                $(pub $field_name: $field_type),*
            }

            #[allow(unused_parens)]
            impl From<($($field_type),*)> for [< $name Parameters >] {
                fn from(($($field_name),*): ($($field_type),*)) -> Self {
                    Self {
                        $($field_name),*
                    }
                }
            }

            $crate::serialize_unit_struct!($format, $name);
        }
    };
}

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
