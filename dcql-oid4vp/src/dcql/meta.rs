// use super::dcql_query::{Format, MetaTypes};
// use validator::ValidationError;

// #[derive(Debug)]
// pub struct MetaContext<'a> {
//     pub format: &'a Format,
// }

// pub fn validate_meta(meta: &Option<MetaTypes>, ctx: &MetaContext) -> Result<(), ValidationError> {
//     let Some(meta_value) = meta else {
//         return Ok(()); // meta is considered an OPTIONAL field. Returns OK if it is none.
//     };

//     match (&ctx.format, meta_value) {
//         (Format::LdpVc, MetaTypes::W3CFormatMeta { type_values }) => validate_w3c_type_values(type_values),
//         (Format::JwtVcJson, MetaTypes::W3CFormatMeta { type_values }) => validate_w3c_type_values(type_values),
//         (Format::DcSdJwt, MetaTypes::SdJwtMeta { vct_values }) => validate_sd_jwt_vct_values(vct_values),
//         (Format::MsoMdoc, MetaTypes::MsoMdocMeta { doctype_value }) => validate_mso_mdoc_doctype(doctype_value),
//         (format, meta_value) => Err(ValidationError::new("incorrect_meta_format")
//             .with_message(format!("{:?} is not compatible with format: {:?}", meta_value, format).into())),
//     }
// }

// fn validate_w3c_type_values(type_values: &[Vec<String>]) -> Result<(), ValidationError> {
//     if type_values.is_empty() {
//         return Err(ValidationError::new("invalid_type_values").with_message("type_values cannot be empty".into()));
//     }

//     for (i, inner_array) in type_values.iter().enumerate() {
//         if inner_array.is_empty() {
//             return Err(ValidationError::new("invalid_type_values")
//                 .with_message(format!("type_values[{}] cannot be empty", i).into()));
//         }

//         for (j, value) in inner_array.iter().enumerate() {
//             if value.is_empty() {
//                 return Err(ValidationError::new("invalid_type_values")
//                     .with_message(format!("type_values[{}][{}] cannot be empty", i, j).into()));
//             }
//         }
//     }

//     Ok(())
// }

// fn validate_sd_jwt_vct_values(vct_values: &[String]) -> Result<(), ValidationError> {
//     if vct_values.is_empty() {
//         return Err(ValidationError::new("invalid_vct_values").with_message("vct_values cannot be empty".into()));
//     }

//     for (i, value) in vct_values.iter().enumerate() {
//         if value.is_empty() {
//             return Err(ValidationError::new("invalid_vct_values")
//                 .with_message(format!("vct_values[{}] cannot be empty", i).into()));
//         }
//     }

//     Ok(())
// }

// fn validate_mso_mdoc_doctype(doctype_value: &str) -> Result<(), ValidationError> {
//     if doctype_value.is_empty() {
//         return Err(ValidationError::new("invalid_doctype_value").with_message("doctype_value cannot be empty".into()));
//     }

//     Ok(())
// }
