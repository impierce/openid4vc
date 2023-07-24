pub mod iso_mdl;
pub mod w3c_verifiable_credentials;

#[macro_export]
macro_rules! credential_format {
    ($format:literal, $name:ty, {$($field_name:ident: $field_type:ty),*}) => {
        paste::paste! {
            #[derive(Debug, Clone, Eq, PartialEq)]
            pub struct $name;
            impl credential_format::Format for $name {
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
