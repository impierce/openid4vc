pub mod authentication;
pub mod collection;
pub mod decoder;
pub mod jwt;
pub mod rfc7519_claims;
pub mod subject_syntax_type;

pub use authentication::{
    sign::Sign,
    subject::{Subject, Subjects},
    validator::{Validator, Validators},
    verify::Verify,
};
pub use collection::Collection;
pub use decoder::Decoder;
pub use rfc7519_claims::RFC7519Claims;
pub use subject_syntax_type::{DidMethod, SubjectSyntaxType};

#[cfg(test)]
pub mod test_utils;

#[macro_export]
macro_rules! builder_fn {
    ($name:ident, $ty:ty) => {
        #[allow(clippy::should_implement_trait)]
        pub fn $name(mut self, value: impl Into<$ty>) -> Self {
            self.$name.replace(value.into());
            self
        }
    };
    ($field:ident, $name:ident, $ty:ty) => {
        #[allow(clippy::should_implement_trait)]
        pub fn $name(mut self, value: impl Into<$ty>) -> Self {
            self.$field.$name.replace(value.into());
            self
        }
    };
}
